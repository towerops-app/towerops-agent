use log::{info, warn};
use serde::Deserialize;
use std::cmp::Ordering;
use std::process::Command;

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

/// Perform self-update by pulling latest image and exiting
/// Returns Ok(true) if update was initiated, Ok(false) if already up to date
pub fn perform_self_update() -> Result<bool, String> {
    let current_ver = current_version();

    // Check if a newer version is available
    match get_latest_version() {
        Ok(latest) => {
            let current = Version::parse(current_ver);
            let latest_version = Version::parse(&latest);

            match (current, latest_version) {
                (Some(curr), Some(lat)) => {
                    if lat <= curr {
                        info!(
                            "Already running latest version ({} <= {})",
                            latest, current_ver
                        );
                        return Ok(false);
                    }

                    info!("Update available: {} -> {}", current_ver, latest);
                }
                _ => {
                    warn!("Could not parse versions, proceeding with update check");
                }
            }
        }
        Err(e) => {
            warn!("Could not check Docker Hub for versions: {}", e);
            // Continue anyway - try to pull and see if anything changed
        }
    }

    // Pull the latest image
    info!("Pulling latest Docker image: {}:latest", DOCKER_IMAGE);
    let output = Command::new("docker")
        .args(["pull", &format!("{}:latest", DOCKER_IMAGE)])
        .output()
        .map_err(|e| format!("Failed to execute docker command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to pull image: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check if the image was actually updated
    if stdout.contains("Image is up to date") || stdout.contains("Already exists") {
        info!("Image is already up to date, no restart needed");
        return Ok(false);
    }

    info!("Successfully pulled new image");
    info!("Exiting to allow restart with new version...");

    // Exit with success code - orchestrator (docker-compose/k8s) will restart with new image
    std::process::exit(0);
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
