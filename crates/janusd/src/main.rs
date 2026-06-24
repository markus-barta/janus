//! # janusd — the Janus daemon
//!
//! Wires `janus-core` + `janus-warden` (+ later `janus-forge`) into the serving
//! binary that will supersede the Go envelope's serving role at `vault.barta.cm`.
//! Until the engine lands, the deployed service is `../../go-envelope`.

fn main() {
    eprintln!(
        "janusd: engine not yet implemented. \
         See PPM JANUS architecture-v1 (JANUS-14 SecretStore, JANUS-21 age, \
         JANUS-22 MCP warden). The live service is the Go envelope in go-envelope/."
    );
    std::process::exit(0);
}
