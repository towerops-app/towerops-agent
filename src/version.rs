// Get version at runtime - prefers BUILD_VERSION from build.rs, falls back to Cargo.toml
fn current_version() -> &'static str {
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


    // Note: check_for_updates() just logs the version, no testing needed
}
