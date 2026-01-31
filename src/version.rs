/// Get version at runtime - prefers BUILD_VERSION from build.rs, falls back to Cargo.toml
pub fn current_version() -> &'static str {
    option_env!("BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Startup check - logs current version
pub fn check_for_updates() {
    let current_ver = current_version();
    crate::log_info!("Current version: {}", current_ver);
    crate::log_info!("Watchtower will automatically update to new versions");
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
        // Version should be in semver-like format (e.g., "0.1.0" or custom BUILD_VERSION)
        // At minimum, should have some content
        assert!(version.len() >= 1);
    }

    #[test]
    fn test_check_for_updates() {
        // This function just logs, but we can call it to verify it doesn't panic
        check_for_updates();
        // If we get here, the function completed without panicking
    }
}
