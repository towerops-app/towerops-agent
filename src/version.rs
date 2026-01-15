use log::{info, warn};
use serde::Deserialize;
use std::process::Command;

const DOCKER_IMAGE: &str = "gmcintire/towerops-agent";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct DockerHubTag {
    last_updated: String,
}

/// Simple startup check - just logs current version and that updates are automatic
pub fn check_for_updates() {
    info!("Current version: {}", CURRENT_VERSION);
    info!("Automatic updates enabled - will check every hour");
}

/// Perform self-update by pulling latest image and exiting
/// This always pulls latest since we use the :latest tag and can't reliably compare versions
/// Returns Ok(true) if update was initiated, Ok(false) if pull showed no changes
pub fn perform_self_update() -> Result<bool, String> {
    // Check if latest tag exists on Docker Hub (quick sanity check)
    match check_latest_exists() {
        Ok(last_updated) => {
            info!(
                "Latest image on Docker Hub was updated at: {}",
                last_updated
            );
        }
        Err(e) => {
            warn!("Could not verify latest tag on Docker Hub: {}", e);
            // Continue anyway - if pull fails we'll catch it below
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

/// Check if the latest tag exists on Docker Hub and return its last_updated timestamp
fn check_latest_exists() -> Result<String, Box<dyn std::error::Error>> {
    let url = format!(
        "https://hub.docker.com/v2/repositories/{}/tags/latest",
        DOCKER_IMAGE
    );

    let response: DockerHubTag = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .call()?
        .into_json()?;

    Ok(response.last_updated)
}
