use std::process::Command;

fn main() {
    // Compile protobuf definitions
    prost_build::compile_protos(&["proto/agent.proto"], &["proto/"]).unwrap();

    // Inject git-based version if available, otherwise use Cargo.toml version
    // This ensures the binary version matches the Docker image tag
    let version = get_version();
    println!("cargo:rustc-env=BUILD_VERSION={}", version);
}

fn get_version() -> String {
    // Try git describe first - gives us the most descriptive version
    // Examples:
    //   v0.2.0          -> "0.2.0"           (exact tag)
    //   v0.2.0-5-g831588e -> "0.2.0.5.831588e" (5 commits after v0.2.0)
    if let Ok(output) = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty=-modified"])
        .output()
    {
        if output.status.success() {
            let desc = String::from_utf8_lossy(&output.stdout).trim().to_string();

            // Parse git describe output
            if let Some(version) = parse_git_describe(&desc) {
                return version;
            }
        }
    }

    // Fallback: Try short commit hash only
    if let Ok(output) = Command::new("git").args(["rev-parse", "--short", "HEAD"]).output() {
        if output.status.success() {
            let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return format!("{}.{}", env!("CARGO_PKG_VERSION"), commit);
        }
    }

    // Final fallback to Cargo.toml version
    env!("CARGO_PKG_VERSION").to_string()
}

fn parse_git_describe(desc: &str) -> Option<String> {
    // Strip 'v' prefix if present
    let desc = desc.strip_prefix('v').unwrap_or(desc);

    // Check for dirty flag
    let dirty = desc.ends_with("-modified");
    let desc = desc.strip_suffix("-modified").unwrap_or(desc);

    if let Some((base, rest)) = desc.split_once('-') {
        // Format: tag-N-ghash (e.g., "0.2.0-5-g831588e")
        let parts: Vec<&str> = rest.split('-').collect();
        if parts.len() == 2 {
            let commit_count = parts[0];
            let hash = parts[1].strip_prefix('g').unwrap_or(parts[1]);
            let version = format!("{}.{}.{}", base, commit_count, hash);
            return Some(if dirty { format!("{}-modified", version) } else { version });
        }
    }

    // No commits after tag, just use the tag
    Some(if dirty { format!("{}-modified", desc) } else { desc.to_string() })
}
