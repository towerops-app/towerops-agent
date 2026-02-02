use super::types::{CommandResponse, MikrotikError, MikrotikResult, SecretString, Sentence};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Stream type that can be either TLS or plain TCP
enum MikrotikStream {
    Tls(Box<TlsStream<TcpStream>>),
    Plain(TcpStream),
}

impl AsyncRead for MikrotikStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MikrotikStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            MikrotikStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MikrotikStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MikrotikStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            MikrotikStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MikrotikStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            MikrotikStream::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MikrotikStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            MikrotikStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// MikroTik RouterOS API client (supports both SSL and plain connections)
pub struct MikrotikClient {
    stream: MikrotikStream,
}

impl MikrotikClient {
    /// Connect to a MikroTik device over SSL (port 8729) and authenticate
    pub async fn connect(
        ip: &str,
        port: u16,
        username: &str,
        password: &SecretString,
    ) -> MikrotikResult<Self> {
        // Create TLS config that accepts any certificate (RouterOS uses self-signed)
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        // Connect TCP
        let addr = format!("{}:{}", ip, port);
        let tcp_stream = match timeout(CONNECTION_TIMEOUT, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(MikrotikError::ConnectionFailed(format!(
                    "TCP connect to {} failed: {}",
                    addr, e
                )))
            }
            Err(_) => return Err(MikrotikError::Timeout),
        };

        // Upgrade to TLS - handle both IP addresses and hostnames
        let domain = if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
            tokio_rustls::rustls::pki_types::ServerName::IpAddress(
                tokio_rustls::rustls::pki_types::IpAddr::from(ip_addr),
            )
        } else {
            tokio_rustls::rustls::pki_types::ServerName::try_from(ip.to_string()).unwrap_or_else(
                |_| {
                    tokio_rustls::rustls::pki_types::ServerName::try_from("mikrotik".to_string())
                        .unwrap()
                },
            )
        };
        let tls_stream =
            match timeout(CONNECTION_TIMEOUT, connector.connect(domain, tcp_stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    return Err(MikrotikError::TlsError(format!(
                        "TLS handshake failed: {}",
                        e
                    )))
                }
                Err(_) => return Err(MikrotikError::Timeout),
            };

        let mut client = Self {
            stream: MikrotikStream::Tls(Box::new(tls_stream)),
        };

        // Authenticate
        client.authenticate(username, password).await?;

        Ok(client)
    }

    /// Connect to a MikroTik device over plain TCP (port 8728) and authenticate
    /// WARNING: Credentials are sent in plaintext - use only for testing or on trusted networks
    pub async fn connect_plain(
        ip: &str,
        port: u16,
        username: &str,
        password: &SecretString,
    ) -> MikrotikResult<Self> {
        // Connect TCP
        let addr = format!("{}:{}", ip, port);
        let tcp_stream = match timeout(CONNECTION_TIMEOUT, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(MikrotikError::ConnectionFailed(format!(
                    "TCP connect to {} failed: {}",
                    addr, e
                )))
            }
            Err(_) => return Err(MikrotikError::Timeout),
        };

        let mut client = Self {
            stream: MikrotikStream::Plain(tcp_stream),
        };

        // Authenticate
        client.authenticate(username, password).await?;

        Ok(client)
    }

    /// Authenticate with the RouterOS device
    async fn authenticate(
        &mut self,
        username: &str,
        password: &SecretString,
    ) -> MikrotikResult<()> {
        let response = self
            .execute(
                "/login",
                &[("name", username), ("password", password.expose())],
            )
            .await?;

        if let Some(err) = response.error {
            return Err(MikrotikError::AuthenticationFailed(err));
        }

        Ok(())
    }

    /// Execute a command and return the response
    pub async fn execute(
        &mut self,
        command: &str,
        args: &[(&str, &str)],
    ) -> MikrotikResult<CommandResponse> {
        // Build and send the command
        let mut words = vec![command.to_string()];
        for (key, value) in args {
            words.push(format!("={}={}", key, value));
        }

        self.send_sentence(&words).await?;

        // Read response sentences until we get !done or !trap
        self.read_response().await
    }

    /// Send a sentence (list of words) to the device
    async fn send_sentence(&mut self, words: &[String]) -> MikrotikResult<()> {
        let mut buf = Vec::new();

        for word in words {
            encode_word(&mut buf, word);
        }
        // Empty word to terminate sentence
        encode_word(&mut buf, "");

        self.stream
            .write_all(&buf)
            .await
            .map_err(|e| MikrotikError::ConnectionFailed(format!("Write failed: {}", e)))?;

        self.stream
            .flush()
            .await
            .map_err(|e| MikrotikError::ConnectionFailed(format!("Flush failed: {}", e)))?;

        Ok(())
    }

    /// Read response sentences from the device
    async fn read_response(&mut self) -> MikrotikResult<CommandResponse> {
        let mut response = CommandResponse::default();

        loop {
            let sentence = self.read_sentence().await?;

            if sentence.is_empty() {
                continue;
            }

            let first_word = &sentence[0];

            match first_word.as_str() {
                "!done" => {
                    // Parse any attributes in the done sentence
                    let attrs = parse_attributes(&sentence[1..]);
                    if !attrs.is_empty() {
                        response.sentences.push(Sentence {
                            attributes: attrs,
                            tag: None,
                        });
                    }
                    break;
                }
                "!trap" => {
                    // Error response
                    let attrs = parse_attributes(&sentence[1..]);
                    let error_msg = attrs
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| "Unknown error".to_string());
                    response.error = Some(error_msg);
                    // Continue reading until !done
                }
                "!re" => {
                    // Result sentence
                    let attrs = parse_attributes(&sentence[1..]);
                    response.sentences.push(Sentence {
                        attributes: attrs,
                        tag: None,
                    });
                }
                "!fatal" => {
                    let attrs = parse_attributes(&sentence[1..]);
                    let error_msg = attrs
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| "Fatal error".to_string());
                    return Err(MikrotikError::CommandFailed(error_msg));
                }
                _ => {
                    // Unknown sentence type, ignore
                }
            }
        }

        Ok(response)
    }

    /// Read a single sentence (list of words until empty word)
    async fn read_sentence(&mut self) -> MikrotikResult<Vec<String>> {
        let mut words = Vec::new();

        loop {
            let word = match timeout(READ_TIMEOUT, self.read_word()).await {
                Ok(Ok(w)) => w,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(MikrotikError::Timeout),
            };

            if word.is_empty() {
                break;
            }

            words.push(word);
        }

        Ok(words)
    }

    /// Read a single word from the stream
    async fn read_word(&mut self) -> MikrotikResult<String> {
        let len = self.read_length().await?;

        if len == 0 {
            return Ok(String::new());
        }

        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| MikrotikError::ConnectionFailed(format!("Read word failed: {}", e)))?;

        String::from_utf8(buf)
            .map_err(|e| MikrotikError::ProtocolError(format!("Invalid UTF-8: {}", e)))
    }

    /// Read the length prefix of a word
    async fn read_length(&mut self) -> MikrotikResult<usize> {
        let mut first = [0u8; 1];
        self.stream
            .read_exact(&mut first)
            .await
            .map_err(|e| MikrotikError::ConnectionFailed(format!("Read length failed: {}", e)))?;

        let first_byte = first[0];

        // RouterOS API length encoding:
        // 0x00-0x7F: 1 byte, value is the length
        // 0x80-0xBF: 2 bytes, length = ((b1 & 0x3F) << 8) | b2
        // 0xC0-0xDF: 3 bytes, length = ((b1 & 0x1F) << 16) | (b2 << 8) | b3
        // 0xE0-0xEF: 4 bytes, length = ((b1 & 0x0F) << 24) | (b2 << 16) | (b3 << 8) | b4
        // 0xF0: 5 bytes, length = (b2 << 24) | (b3 << 16) | (b4 << 8) | b5

        if first_byte < 0x80 {
            Ok(first_byte as usize)
        } else if first_byte < 0xC0 {
            let mut buf = [0u8; 1];
            self.stream.read_exact(&mut buf).await.map_err(|e| {
                MikrotikError::ConnectionFailed(format!("Read length failed: {}", e))
            })?;
            Ok((((first_byte & 0x3F) as usize) << 8) | (buf[0] as usize))
        } else if first_byte < 0xE0 {
            let mut buf = [0u8; 2];
            self.stream.read_exact(&mut buf).await.map_err(|e| {
                MikrotikError::ConnectionFailed(format!("Read length failed: {}", e))
            })?;
            Ok((((first_byte & 0x1F) as usize) << 16)
                | ((buf[0] as usize) << 8)
                | (buf[1] as usize))
        } else if first_byte < 0xF0 {
            let mut buf = [0u8; 3];
            self.stream.read_exact(&mut buf).await.map_err(|e| {
                MikrotikError::ConnectionFailed(format!("Read length failed: {}", e))
            })?;
            Ok((((first_byte & 0x0F) as usize) << 24)
                | ((buf[0] as usize) << 16)
                | ((buf[1] as usize) << 8)
                | (buf[2] as usize))
        } else {
            let mut buf = [0u8; 4];
            self.stream.read_exact(&mut buf).await.map_err(|e| {
                MikrotikError::ConnectionFailed(format!("Read length failed: {}", e))
            })?;
            Ok(((buf[0] as usize) << 24)
                | ((buf[1] as usize) << 16)
                | ((buf[2] as usize) << 8)
                | (buf[3] as usize))
        }
    }

    /// Close the connection
    pub async fn close(&mut self) -> MikrotikResult<()> {
        // Send quit command
        let _ = self.execute("/quit", &[]).await;
        Ok(())
    }
}

/// Encode a word with its length prefix
fn encode_word(buf: &mut Vec<u8>, word: &str) {
    let len = word.len();
    encode_length(buf, len);
    buf.extend_from_slice(word.as_bytes());
}

/// Encode a length using RouterOS API encoding
fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x4000 {
        buf.push(((len >> 8) as u8) | 0x80);
        buf.push((len & 0xFF) as u8);
    } else if len < 0x200000 {
        buf.push(((len >> 16) as u8) | 0xC0);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
    } else if len < 0x10000000 {
        buf.push(((len >> 24) as u8) | 0xE0);
        buf.push(((len >> 16) & 0xFF) as u8);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
    } else {
        buf.push(0xF0);
        buf.push(((len >> 24) & 0xFF) as u8);
        buf.push(((len >> 16) & 0xFF) as u8);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Parse attributes from response words (=key=value format)
fn parse_attributes(words: &[String]) -> HashMap<String, String> {
    let mut attrs = HashMap::new();

    for word in words {
        if let Some(kv) = word.strip_prefix('=') {
            if let Some((key, value)) = kv.split_once('=') {
                attrs.insert(key.to_string(), value.to_string());
            }
        }
    }

    attrs
}

/// Custom certificate verifier that accepts any certificate
/// RouterOS devices use self-signed certificates
#[derive(Debug)]
struct NoVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for encode_length - the RouterOS API length encoding

    #[test]
    fn test_encode_length_single_byte() {
        // Lengths 0-127 use single byte
        let mut buf = Vec::new();
        encode_length(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        let mut buf = Vec::new();
        encode_length(&mut buf, 1);
        assert_eq!(buf, vec![0x01]);

        let mut buf = Vec::new();
        encode_length(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);
    }

    #[test]
    fn test_encode_length_two_bytes() {
        // Lengths 128-16383 use two bytes (0x80-0xBF prefix)
        let mut buf = Vec::new();
        encode_length(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x80]);

        let mut buf = Vec::new();
        encode_length(&mut buf, 255);
        assert_eq!(buf, vec![0x80, 0xFF]);

        let mut buf = Vec::new();
        encode_length(&mut buf, 256);
        assert_eq!(buf, vec![0x81, 0x00]);

        let mut buf = Vec::new();
        encode_length(&mut buf, 16383);
        assert_eq!(buf, vec![0xBF, 0xFF]);
    }

    #[test]
    fn test_encode_length_three_bytes() {
        // Lengths 16384-2097151 use three bytes (0xC0-0xDF prefix)
        let mut buf = Vec::new();
        encode_length(&mut buf, 16384);
        assert_eq!(buf, vec![0xC0, 0x40, 0x00]);

        let mut buf = Vec::new();
        encode_length(&mut buf, 2097151);
        assert_eq!(buf, vec![0xDF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_encode_length_four_bytes() {
        // Lengths 2097152-268435455 use four bytes (0xE0-0xEF prefix)
        let mut buf = Vec::new();
        encode_length(&mut buf, 2097152);
        assert_eq!(buf, vec![0xE0, 0x20, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_length_five_bytes() {
        // Lengths >= 268435456 use five bytes (0xF0 prefix)
        let mut buf = Vec::new();
        encode_length(&mut buf, 268435456);
        assert_eq!(buf, vec![0xF0, 0x10, 0x00, 0x00, 0x00]);
    }

    // Tests for encode_word

    #[test]
    fn test_encode_word_empty() {
        let mut buf = Vec::new();
        encode_word(&mut buf, "");
        assert_eq!(buf, vec![0x00]); // Just length byte of 0
    }

    #[test]
    fn test_encode_word_simple() {
        let mut buf = Vec::new();
        encode_word(&mut buf, "/login");
        assert_eq!(buf, vec![0x06, b'/', b'l', b'o', b'g', b'i', b'n']);
    }

    #[test]
    fn test_encode_word_with_argument() {
        let mut buf = Vec::new();
        encode_word(&mut buf, "=name=admin");
        assert_eq!(
            buf,
            vec![0x0B, b'=', b'n', b'a', b'm', b'e', b'=', b'a', b'd', b'm', b'i', b'n']
        );
    }

    // Tests for parse_attributes

    #[test]
    fn test_parse_attributes_empty() {
        let words: Vec<String> = vec![];
        let attrs = parse_attributes(&words);
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_parse_attributes_single() {
        let words = vec!["=name=MyRouter".to_string()];
        let attrs = parse_attributes(&words);
        assert_eq!(attrs.get("name"), Some(&"MyRouter".to_string()));
    }

    #[test]
    fn test_parse_attributes_multiple() {
        let words = vec![
            "=name=MyRouter".to_string(),
            "=model=RB450Gx4".to_string(),
            "=version=7.10".to_string(),
        ];
        let attrs = parse_attributes(&words);
        assert_eq!(attrs.get("name"), Some(&"MyRouter".to_string()));
        assert_eq!(attrs.get("model"), Some(&"RB450Gx4".to_string()));
        assert_eq!(attrs.get("version"), Some(&"7.10".to_string()));
    }

    #[test]
    fn test_parse_attributes_with_equals_in_value() {
        // Value contains equals sign - split_once preserves the rest
        let words = vec!["=comment=a=b=c".to_string()];
        let attrs = parse_attributes(&words);
        assert_eq!(attrs.get("comment"), Some(&"a=b=c".to_string()));
    }

    #[test]
    fn test_parse_attributes_ignores_non_attribute() {
        let words = vec![
            "!re".to_string(), // Not an attribute
            "=name=test".to_string(),
        ];
        let attrs = parse_attributes(&words);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs.get("name"), Some(&"test".to_string()));
    }

    #[test]
    fn test_parse_attributes_empty_value() {
        let words = vec!["=disabled=".to_string()];
        let attrs = parse_attributes(&words);
        assert_eq!(attrs.get("disabled"), Some(&"".to_string()));
    }
}
