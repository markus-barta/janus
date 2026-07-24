//! Fixed managed-service host orchestration agent.

#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = janus_host::agent::run_from_system() {
        eprintln!(
            "janus-managed-host-agent denied reason_code={} value_returned=false",
            error.reason_code()
        );
        std::process::exit(1);
    }
}
