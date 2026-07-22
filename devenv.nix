{ pkgs, ... }:

{
  packages = with pkgs; [
    age
    cargo
    clippy
    cosign
    gh
    go_1_26
    gotools
    rustc
    rustfmt
  ];

  enterShell = ''
    echo "Janus dev environment"
    echo "  rust: cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings"
    echo "  go:   cd go-envelope && go test ./..."
  '';
}
