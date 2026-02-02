use russh::client;
use russh::keys::PublicKey;
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SshError {
    #[error("SSH connection failed: {0}")]
    ConnectionFailed(String),
    #[error("SSH authentication failed")]
    AuthenticationFailed,
    #[error("SSH command execution failed: {0}")]
    CommandFailed(String),
    #[error("SSH I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("SSH protocol error: {0}")]
    Protocol(#[from] russh::Error),
}

pub type SshResult<T> = Result<T, SshError>;

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        // Accept any server key (similar to SSH -o StrictHostKeyChecking=no)
        // In production, you might want to verify against known_hosts
        let _ = server_public_key; // Suppress unused warning
        async { Ok(true) }
    }
}

pub struct SshClient {
    session: client::Handle<Client>,
}

impl SshClient {
    /// Connect to an SSH server and authenticate with password
    pub async fn connect(host: &str, port: u32, username: &str, password: &str) -> SshResult<Self> {
        let config = client::Config::default();
        let sh = Client;

        tracing::debug!("Connecting to {}:{} as {}", host, port, username);

        let mut session = client::connect(Arc::new(config), (host, port as u16), sh)
            .await
            .map_err(|e| SshError::ConnectionFailed(e.to_string()))?;

        let auth_result = session
            .authenticate_password(username, password)
            .await
            .map_err(|e| SshError::ConnectionFailed(e.to_string()))?;

        if !auth_result.success() {
            return Err(SshError::AuthenticationFailed);
        }

        tracing::debug!("SSH authentication successful");

        Ok(Self { session })
    }

    /// Execute a command and return the output as a String
    pub async fn execute_command(&mut self, command: &str) -> SshResult<String> {
        tracing::debug!("Executing SSH command: {}", command);

        let mut channel = self
            .session
            .channel_open_session()
            .await
            .map_err(|e| SshError::CommandFailed(e.to_string()))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| SshError::CommandFailed(e.to_string()))?;

        let mut output = Vec::new();
        let mut stderr_output = Vec::new();

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };

            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    output.extend_from_slice(data);
                }
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    // stderr
                    stderr_output.extend_from_slice(data);
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    tracing::debug!("Command exit status: {}", exit_status);
                    if exit_status != 0 {
                        let stderr_str = String::from_utf8_lossy(&stderr_output);
                        return Err(SshError::CommandFailed(format!(
                            "Command exited with status {}: {}",
                            exit_status, stderr_str
                        )));
                    }
                }
                russh::ChannelMsg::Eof => {
                    break;
                }
                _ => {}
            }
        }

        channel
            .eof()
            .await
            .map_err(|e| SshError::CommandFailed(e.to_string()))?;

        channel
            .close()
            .await
            .map_err(|e| SshError::CommandFailed(e.to_string()))?;

        let output_str = String::from_utf8_lossy(&output).to_string();
        tracing::debug!(
            "Command output: {} bytes, {} lines",
            output_str.len(),
            output_str.lines().count()
        );

        Ok(output_str)
    }

    /// Close the SSH session
    pub async fn close(self) -> SshResult<()> {
        self.session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await?;
        Ok(())
    }
}
