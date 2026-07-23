{
  description = "Janus secret-handling engine";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      workspaceVersion = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          janus-engine = pkgs.rustPlatform.buildRustPackage {
            pname = "janus-engine";
            version = workspaceVersion;
            src = ./.;

            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "--bins"
              "-p"
              "janusd"
              "-p"
              "janus-warden"
            ];
            cargoTestFlags = [ "--workspace" ];

            installPhase = ''
              runHook preInstall
              release_dir="target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release"
              install -Dm755 "$release_dir/janusd" "$out/bin/janusd"
              install -Dm755 "$release_dir/janusd-use" "$out/bin/janusd-use"
              install -Dm755 "$release_dir/janusd-admin" "$out/bin/janusd-admin"
              install -Dm755 "$release_dir/janusd-web-transactiond" "$out/bin/janusd-web-transactiond"
              install -Dm755 "$release_dir/janus-warden" "$out/bin/janus-warden"
              runHook postInstall
            '';

            meta = {
              description = "Janus split-plane permit broker, administration runtime, and reference-only Warden";
              homepage = "https://github.com/markus-barta/janus";
              license = pkgs.lib.licenses.agpl3Only;
              platforms = supportedSystems;
              mainProgram = "janusd-use";
            };
          };
        in
        {
          default = janus-engine;
          inherit janus-engine;
        }
      );
    };
}
