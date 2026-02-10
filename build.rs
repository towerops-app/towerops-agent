fn main() {
    // Compile protobuf definitions
    prost_build::compile_protos(&["proto/agent.proto"], &["proto/"]).unwrap();

    // Compile C helper for SNMP
    cc::Build::new()
        .file("native/snmp_helper.c")
        .include("native")
        .compile("snmp_helper");

    // Link against netsnmp library
    println!("cargo:rustc-link-lib=netsnmp");

    // On macOS with Homebrew, net-snmp depends on OpenSSL which is keg-only
    // (not linked into /usr/local/lib). Add the OpenSSL library path so the
    // linker can find libcrypto.
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("brew")
            .args(["--prefix", "openssl@3"])
            .output()
        {
            if output.status.success() {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                println!("cargo:rustc-link-search={}/lib", prefix);
            }
        }
    }

    // Inject compile timestamp as version
    // This allows tracking when a specific agent binary was built
    let version = get_version();
    println!("cargo:rustc-env=BUILD_VERSION={}", version);
}

fn get_version() -> String {
    // Generate RFC 3339 timestamp at compile time
    // Format: YYYY-MM-DDTHH:MM:SSZ
    let now = chrono::Utc::now();
    now.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
