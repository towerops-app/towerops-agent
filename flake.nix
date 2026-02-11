{
  description = "towerops-agent - Go SNMP polling agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
            pkgs.golangci-lint
            pkgs.protobuf
            pkgs.protoc-gen-go
            pkgs.git
          ];

          env = {
            PROTOC = "${pkgs.protobuf}/bin/protoc";
          };
        };
      });
}
