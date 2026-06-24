{ pkgs, ... }:

{
  packages = with pkgs; [
    cargo
    clippy
    go
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
