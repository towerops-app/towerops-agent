use log::{info, warn};
use serde::Deserialize;

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

/// Check if a newer version of the Docker image is available
pub fn check_for_updates() {
    info!("Current version: {}", CURRENT_VERSION);
    info!("Checking for newer Docker image versions...");

    match check_docker_hub() {
        Ok(Some(latest_version)) => {
            if latest_version != CURRENT_VERSION {
                warn!(
                    "⚠️  Newer version available: {} (current: {})",
                    latest_version, CURRENT_VERSION
                );
                warn!("   Update with: docker pull {}:latest", DOCKER_IMAGE);
            } else {
                info!("✓ Running latest version ({})", CURRENT_VERSION);
            }
        }
        Ok(None) => {
            info!("Unable to determine latest version from Docker Hub");
        }
        Err(e) => {
            warn!("Failed to check for updates: {}", e);
        }
    }
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
