use log::{info, warn};
use serde::Deserialize;
use std::process::Command;

const DOCKER_IMAGE: &str = "gmcintire/towerops-agent";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct DockerHubResponse {
    results: Vec<DockerHubTag>,
}

#[derive(Debug, Deserialize)]
struct DockerHubTag {
    name: String,
    #[allow(dead_code)]
    last_updated: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
}

/// Check if a newer version of the Docker image is available
pub fn check_for_updates() {
    info!("Current version: {}", CURRENT_VERSION);
    info!("Checking for newer Docker image versions...");

    match get_update_info() {
        Ok(info) => {
            if info.update_available {
                if let Some(ref latest) = info.latest_version {
                    warn!(
                        "⚠️  Newer version available: {} (current: {})",
                        latest, info.current_version
                    );
                    warn!("   Update with: docker pull {}:latest", DOCKER_IMAGE);
                }
            } else {
                info!("✓ Running latest version ({})", info.current_version);
            }
        }
        Err(e) => {
            warn!("Failed to check for updates: {}", e);
        }
    }
}

/// Get update information without logging
pub fn get_update_info() -> Result<UpdateInfo, String> {
    let latest_version = check_docker_hub().map_err(|e| e.to_string())?;
    let update_available = if let Some(ref latest) = latest_version {
        latest != CURRENT_VERSION
    } else {
        false
    };

    Ok(UpdateInfo {
        current_version: CURRENT_VERSION.to_string(),
        latest_version,
        update_available,
    })
}

/// Perform self-update by pulling new image and exiting
/// Returns Ok(true) if update was initiated, Ok(false) if already up-to-date
pub fn perform_self_update() -> Result<bool, String> {
    let info = get_update_info()?;

    if !info.update_available {
        info!("Already running latest version, no update needed");
        return Ok(false);
    }

    if let Some(ref latest) = info.latest_version {
        warn!(
            "Performing self-update: {} -> {}",
            info.current_version, latest
        );

        // Pull the new image
        info!("Pulling new Docker image: {}:latest", DOCKER_IMAGE);
        let output = Command::new("docker")
            .args(["pull", &format!("{}:latest", DOCKER_IMAGE)])
            .output()
            .map_err(|e| format!("Failed to execute docker command: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to pull image: {}", stderr));
        }

        info!("Successfully pulled new image");
        info!("Exiting to allow restart with new version...");

        // Exit with success code - orchestrator (docker-compose/k8s) will restart with new image
        std::process::exit(0);
    }

    Ok(true)
}

fn check_docker_hub() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://hub.docker.com/v2/repositories/{}/tags?page_size=10",
        DOCKER_IMAGE
    );

    let response: DockerHubResponse = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .call()?
        .into_json()?;

    // Look for version tags (e.g., "0.1.0", "0.2.0")
    // Ignore "latest" tag as it doesn't tell us the actual version
    let version_tags: Vec<&str> = response
        .results
        .iter()
        .map(|t| t.name.as_str())
        .filter(|name| !name.eq_ignore_ascii_case("latest"))
        .filter(|name| is_semver(name))
        .collect();

    if let Some(latest) = version_tags.first() {
        Ok(Some(latest.to_string()))
    } else {
        // If no version tags found, try to get info from "latest" tag
        // but we can't determine actual version number
        Ok(None)
    }
}

fn is_semver(s: &str) -> bool {
    // Simple check: version string should match pattern like "0.1.0" or "v0.1.0"
    let s = s.strip_prefix('v').unwrap_or(s);
    let parts: Vec<&str> = s.split('.').collect();

    parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}
