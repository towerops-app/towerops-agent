use std::collections::HashMap;

pub use crate::secret::SecretString;

/// Error types for MikroTik operations
#[derive(Debug)]
pub enum MikrotikError {
    ConnectionFailed(String),
    AuthenticationFailed(String),
    CommandFailed(String),
    Timeout,
    TlsError(String),
    ProtocolError(String),
}

impl std::fmt::Display for MikrotikError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            Self::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::TlsError(msg) => write!(f, "TLS error: {}", msg),
            Self::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl std::error::Error for MikrotikError {}

pub type MikrotikResult<T> = Result<T, MikrotikError>;

/// A sentence from a RouterOS API response (key-value pairs)
#[derive(Debug, Clone, Default)]
pub struct Sentence {
    pub attributes: HashMap<String, String>,
    #[allow(dead_code)] // Reserved for future use with tagged API commands
    pub tag: Option<String>,
}

/// Response from a RouterOS API command
#[derive(Debug, Clone, Default)]
pub struct CommandResponse {
    pub sentences: Vec<Sentence>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mikrotik_error_display_connection_failed() {
        let err = MikrotikError::ConnectionFailed("refused".to_string());
        assert_eq!(format!("{}", err), "Connection failed: refused");
    }

    #[test]
    fn test_mikrotik_error_display_auth_failed() {
        let err = MikrotikError::AuthenticationFailed("bad password".to_string());
        assert_eq!(format!("{}", err), "Authentication failed: bad password");
    }

    #[test]
    fn test_mikrotik_error_display_command_failed() {
        let err = MikrotikError::CommandFailed("no such command".to_string());
        assert_eq!(format!("{}", err), "Command failed: no such command");
    }

    #[test]
    fn test_mikrotik_error_display_timeout() {
        let err = MikrotikError::Timeout;
        assert_eq!(format!("{}", err), "Operation timed out");
    }

    #[test]
    fn test_mikrotik_error_display_tls_error() {
        let err = MikrotikError::TlsError("certificate invalid".to_string());
        assert_eq!(format!("{}", err), "TLS error: certificate invalid");
    }

    #[test]
    fn test_mikrotik_error_display_protocol_error() {
        let err = MikrotikError::ProtocolError("unexpected response".to_string());
        assert_eq!(format!("{}", err), "Protocol error: unexpected response");
    }

    #[test]
    fn test_mikrotik_error_is_error_trait() {
        let err: &dyn std::error::Error = &MikrotikError::Timeout;
        assert_eq!(format!("{}", err), "Operation timed out");
    }

    #[test]
    fn test_sentence_default() {
        let sentence = Sentence::default();
        assert!(sentence.attributes.is_empty());
        assert!(sentence.tag.is_none());
    }

    #[test]
    fn test_command_response_default() {
        let response = CommandResponse::default();
        assert!(response.sentences.is_empty());
        assert!(response.error.is_none());
    }
}
