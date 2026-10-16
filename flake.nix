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
        # These stable releases are newer than the locked nixpkgs packages.
        git = pkgs.git.overrideAttrs (old: {
          version = "2.56.0";
          src = pkgs.fetchurl {
            url = "https://www.kernel.org/pub/software/scm/git/git-2.56.0.tar.xz";
            hash = "sha256-JsVsKWs4wGlbJvqV9HXx0BcE0tOOc0ZcowsLL13HidM=";
          };
          # Git 2.56 includes the Darwin Unicode fix already.
          patches = builtins.filter
            (patch: !(pkgs.lib.hasSuffix "darwin-unicode-filename-fix.patch" (toString patch)))
            old.patches;
          postPatch = old.postPatch + ''
            # The new test's redirect must quote its space-containing test directory.
            substituteInPlace t/t1017-cat-file-remote-object-info.sh \
              --replace-fail '> $daemon_parent/hello' '> "$daemon_parent/hello"'
          '';
        });
        golangci-lint = pkgs.golangci-lint.overrideAttrs {
          version = "2.15.0";
          src = pkgs.fetchFromGitHub {
            owner = "golangci";
            repo = "golangci-lint";
            tag = "v2.15.0";
            hash = "sha256-m9PoJHescRuT9DiKsb6LL+lQlc7RKAWDiRyf8pNMffA=";
          };
          vendorHash = "sha256-gWbhZc/BJwuiwyTMaR1ShEBI1lo0bGLCXsdj5n91baw=";
        };
        gopls = pkgs.gopls.overrideAttrs {
          version = "0.24.0";
          src = pkgs.fetchFromGitHub {
            owner = "golang";
            repo = "tools";
            tag = "gopls/v0.24.0";
            hash = "sha256-MX66CdQDrM8wdDmrAHRLvoKH9Y5hJ97A6Z1HrmFuHc0=";
          };
          vendorHash = "sha256-YGB5qzoyU4I1yp9rxaE3KZLphTcn0DJRG/Z1WvP6pVM=";
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go_1_27
            golangci-lint
            pkgs.protobuf
            pkgs.protoc-gen-go
            git
            gopls
            pkgs.delve
          ];

          env = {
            PROTOC = "${pkgs.protobuf}/bin/protoc";
          };

          shellHook = ''
            echo "towerops-agent dev shell"
            echo "  go test ./...    - run tests"
            echo "  go build ./...   - build"
            echo "  make proto       - regenerate protobuf"
          '';
        };
      });
}
