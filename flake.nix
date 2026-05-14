{
  description = "Janus — Inspire LLM-vault connector (Rust workspace)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        toolchain = fenix.packages.${system}.fromToolchainFile {
          file = ./rust-toolchain.toml;
          # First run: replace with actual sha (nix will print on mismatch).
          sha256 = pkgs.lib.fakeSha256;
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            toolchain
            pkgs.cargo-deny
            pkgs.cargo-nextest
            pkgs.openssl
            pkgs.pkg-config
          ];

          RUST_BACKTRACE = "1";
        };
      });
}
