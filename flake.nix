{
  description = "towerops-agent - Rust SNMP polling agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.protobuf
            pkgs.net-snmp
            pkgs.openssl
            pkgs.pkg-config
            pkgs.git
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.apple-sdk_15
          ];

          env = {
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            # Help netsnmp-sys find the library
            NET_SNMP_CONFIG = "${pkgs.net-snmp}/bin/net-snmp-config";
            # Help cargo find OpenSSL for linking
            PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
            OPENSSL_DIR = "${pkgs.openssl.dev}";
            OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
            OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
          };

          shellHook = ''
            # Set RUSTFLAGS to find OpenSSL libraries at link time
            export RUSTFLAGS="-L ${pkgs.openssl.out}/lib"
          '';
        };
      });
}
