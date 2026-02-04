use zeroize::Zeroize;

/// A wrapper for sensitive strings (passwords, tokens) that prevents accidental logging.
/// - Debug and Display show "[REDACTED]" instead of the actual value
/// - The inner value is zeroized on drop using volatile writes (cannot be optimized away)
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Access the secret value. Use sparingly and never log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_string_expose() {
        let secret = SecretString::new("my_password");
        assert_eq!(secret.expose(), "my_password");
    }

    #[test]
    fn test_secret_string_debug_is_redacted() {
        let secret = SecretString::new("my_password");
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("my_password"));
    }

    #[test]
    fn test_secret_string_display_is_redacted() {
        let secret = SecretString::new("my_password");
        let display_output = format!("{}", secret);
        assert_eq!(display_output, "[REDACTED]");
        assert!(!display_output.contains("my_password"));
    }

    #[test]
    fn test_secret_string_clone() {
        let secret = SecretString::new("my_password");
        let cloned = secret.clone();
        assert_eq!(cloned.expose(), "my_password");
    }

    #[test]
    fn test_secret_string_empty() {
        let secret = SecretString::new("");
        assert!(secret.is_empty());
        assert!(secret.expose().is_empty());
    }

    #[test]
    fn test_secret_string_is_empty() {
        let secret = SecretString::new("not_empty");
        assert!(!secret.is_empty());
    }
}
