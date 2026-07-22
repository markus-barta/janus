{ pkgs, ... }:

{
  packages = with pkgs; [
    age
    cargo
    cargo-audit
    clippy
    cosign
    gh
    gitleaks
    go_1_26
    govulncheck
    gotools
    rustc
    rustfmt
    trivy
  ];

  enterShell = ''
    echo "Janus dev environment"
    echo "  rust: cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings"
    echo "  go:   cd go-envelope && go test ./..."
    echo "  sec:  scripts/run-security-gates.sh"
  '';
}
