/// Get compile timestamp at runtime - returns RFC 3339 formatted timestamp from build.rs
/// Format: YYYY-MM-DDTHH:MM:SSZ (e.g., "2025-02-09T15:30:45Z")
pub fn current_version() -> &'static str {
    option_env!("BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Startup check - logs current version
pub fn check_for_updates() {
    let current_ver = current_version();
    tracing::info!("Current version: {}", current_ver);
    tracing::info!("Watchtower will automatically update to new versions");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version() {
        let version = current_version();
        assert!(!version.is_empty(), "Version should not be empty");
        // Version comes from env! macro at compile time
        // Just verify it's a non-empty string
    }

    #[test]
    fn test_current_version_format() {
        let version = current_version();
        // Version should be RFC 3339 timestamp format (YYYY-MM-DDTHH:MM:SSZ)
        // Regex: ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$
        let rfc3339_pattern = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$").unwrap();
        assert!(
            rfc3339_pattern.is_match(version),
            "Version should be RFC 3339 timestamp, got: {}",
            version
        );
    }

    #[test]
    fn test_check_for_updates() {
        // This function just logs, but we can call it to verify it doesn't panic
        check_for_updates();
        // If we get here, the function completed without panicking
    }
}
