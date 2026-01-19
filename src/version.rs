use log::{info, warn};
use serde::Deserialize;
use std::cmp::Ordering;

const DOCKER_IMAGE: &str = "gmcintire/towerops-agent";

// Get version at runtime - prefers BUILD_VERSION from build.rs, falls back to Cargo.toml
fn current_version() -> &'static str {
    option_env!("BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Deserialize)]
struct DockerHubResponse {
    results: Vec<DockerHubTag>,
}

#[derive(Debug, Deserialize)]
struct DockerHubTag {
    name: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 3 {
            return None;
        }

        Some(Version {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

/// Startup check - logs current version and checks for updates
pub fn check_for_updates() {
    let current_ver = current_version();
    info!("Current version: {}", current_ver);

    match get_latest_version() {
        Ok(latest) => {
            let current = Version::parse(current_ver);
            let latest_version = Version::parse(&latest);

            match (current, latest_version) {
                (Some(curr), Some(lat)) => {
                    if lat > curr {
                        warn!(
                            "⚠️  Newer version available: {} (current: {})",
                            latest, current_ver
                        );
                        warn!("   Automatic updates will pull new version every hour");
                    } else {
                        info!("✓ Running latest version ({})", current_ver);
                    }
                }
                _ => {
                    info!("Could not compare versions, automatic updates enabled");
                }
            }
        }
        Err(e) => {
            warn!("Could not check for updates: {}", e);
            info!("Automatic updates enabled - will check every hour");
        }
    }
}

/// Get the latest version from Docker Hub
fn get_latest_version() -> Result<String, Box<dyn std::error::Error>> {
    let url = format!(
        "https://hub.docker.com/v2/repositories/{}/tags?page_size=100",
        DOCKER_IMAGE
    );

    let response: DockerHubResponse = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .call()?
        .into_json()?;

    extract_latest_version_from_response(response)
}

/// Extract the latest version from Docker Hub response
fn extract_latest_version_from_response(
    response: DockerHubResponse,
) -> Result<String, Box<dyn std::error::Error>> {
    // Filter for semver tags and find the latest
    let mut versions: Vec<Version> = response
        .results
        .iter()
        .filter_map(|tag| Version::parse(&tag.name))
        .collect();

    versions.sort();
    versions.reverse(); // Highest version first

    versions
        .first()
        .map(|v| format!("{}.{}.{}", v.major, v.minor, v.patch))
        .ok_or_else(|| "No valid semver tags found".into())
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
    fn test_version_parse_valid() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_version_parse_with_v_prefix() {
        let v = Version::parse("v2.5.8").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 5);
        assert_eq!(v.patch, 8);
    }

    #[test]
    fn test_version_parse_invalid() {
        assert!(Version::parse("1.2").is_none());
        assert!(Version::parse("1.2.3.4").is_none());
        assert!(Version::parse("a.b.c").is_none());
        assert!(Version::parse("1.2.x").is_none());
        assert!(Version::parse("").is_none());
    }

    #[test]
    fn test_version_comparison_major() {
        let v1 = Version::parse("2.0.0").unwrap();
        let v2 = Version::parse("1.9.9").unwrap();
        assert!(v1 > v2);
        assert!(v2 < v1);
    }

    #[test]
    fn test_version_comparison_minor() {
        let v1 = Version::parse("1.5.0").unwrap();
        let v2 = Version::parse("1.4.9").unwrap();
        assert!(v1 > v2);
        assert!(v2 < v1);
    }

    #[test]
    fn test_version_comparison_patch() {
        let v1 = Version::parse("1.2.4").unwrap();
        let v2 = Version::parse("1.2.3").unwrap();
        assert!(v1 > v2);
        assert!(v2 < v1);
    }

    #[test]
    fn test_version_comparison_equal() {
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.3").unwrap();
        assert_eq!(v1, v2);
        assert!(!(v1 > v2));
        assert!(!(v1 < v2));
    }

    #[test]
    fn test_version_sorting() {
        let mut versions = vec![
            Version::parse("1.2.3").unwrap(),
            Version::parse("2.0.0").unwrap(),
            Version::parse("1.5.0").unwrap(),
            Version::parse("1.2.10").unwrap(),
        ];
        versions.sort();
        assert_eq!(versions[0], Version::parse("1.2.3").unwrap());
        assert_eq!(versions[1], Version::parse("1.2.10").unwrap());
        assert_eq!(versions[2], Version::parse("1.5.0").unwrap());
        assert_eq!(versions[3], Version::parse("2.0.0").unwrap());
    }

    #[test]
    fn test_dockerhub_response_deserialize() {
        let json = r#"{"results":[{"name":"v1.0.0"},{"name":"v1.0.1"}]}"#;
        let response: DockerHubResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.results.len(), 2);
        assert_eq!(response.results[0].name, "v1.0.0");
        assert_eq!(response.results[1].name, "v1.0.1");
    }

    #[test]
    fn test_extract_latest_version_from_response() {
        let response = DockerHubResponse {
            results: vec![
                DockerHubTag {
                    name: "v1.0.0".to_string(),
                },
                DockerHubTag {
                    name: "v1.2.0".to_string(),
                },
                DockerHubTag {
                    name: "v1.1.5".to_string(),
                },
                DockerHubTag {
                    name: "latest".to_string(),
                }, // Should be ignored
            ],
        };

        let latest = extract_latest_version_from_response(response).unwrap();
        assert_eq!(latest, "1.2.0");
    }

    #[test]
    fn test_extract_latest_version_no_valid_tags() {
        let response = DockerHubResponse {
            results: vec![
                DockerHubTag {
                    name: "latest".to_string(),
                },
                DockerHubTag {
                    name: "main".to_string(),
                },
            ],
        };

        let result = extract_latest_version_from_response(response);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No valid semver"));
    }

    #[test]
    fn test_extract_latest_version_empty() {
        let response = DockerHubResponse { results: vec![] };

        let result = extract_latest_version_from_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_debug() {
        let v = Version {
            major: 1,
            minor: 2,
            patch: 3,
        };
        let debug_str = format!("{:?}", v);
        assert!(debug_str.contains("1"));
        assert!(debug_str.contains("2"));
        assert!(debug_str.contains("3"));
    }

    // Note: check_for_updates() and get_latest_version() are tested via integration tests
    // as they require network access to Docker Hub
}
