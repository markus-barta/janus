//! Fixed host-local Janus envelope executor.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::time::SystemTime;

use janus_host::{
    maximum_control_bytes, maximum_packet_bytes, parse_control, parse_quarantine_control,
    read_bounded_input, HostExecutor, HostExecutorOutcome,
};

fn main() {
    if let Err(reason_code) = run() {
        eprintln!("janus-host-executor denied reason_code={reason_code} value_returned=false");
        std::process::exit(1);
    }
}

fn run() -> Result<(), &'static str> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 1 {
        return Err("host_executor_arguments_denied");
    }
    let executor = HostExecutor::from_system().map_err(|error| error.reason_code())?;
    let now = SystemTime::now();
    let outcomes = match args[0].as_str() {
        "install" => {
            let packet = read_bounded_input(&mut io::stdin().lock(), maximum_packet_bytes())
                .map_err(|error| error.reason_code())?;
            vec![executor
                .install(&packet, now)
                .map_err(|error| error.reason_code())?]
        }
        "restore" => executor
            .restore_all(now)
            .map_err(|error| error.reason_code())?,
        "commit" => {
            let raw = read_bounded_input(&mut io::stdin().lock(), maximum_control_bytes())
                .map_err(|error| error.reason_code())?;
            let request = parse_control(&raw).map_err(|error| error.reason_code())?;
            vec![executor
                .commit(&request)
                .map_err(|error| error.reason_code())?]
        }
        "rollback" => {
            let raw = read_bounded_input(&mut io::stdin().lock(), maximum_control_bytes())
                .map_err(|error| error.reason_code())?;
            let request = parse_control(&raw).map_err(|error| error.reason_code())?;
            vec![executor
                .rollback(&request, now)
                .map_err(|error| error.reason_code())?]
        }
        "quarantine" | "restore-quarantine" | "purge-quarantine" => {
            let raw = read_bounded_input(&mut io::stdin().lock(), maximum_control_bytes())
                .map_err(|error| error.reason_code())?;
            let request = parse_quarantine_control(&raw).map_err(|error| error.reason_code())?;
            vec![match args[0].as_str() {
                "quarantine" => executor.quarantine(&request),
                "restore-quarantine" => executor.restore_quarantine(&request, now),
                "purge-quarantine" => executor.purge_quarantine(&request, now),
                _ => unreachable!("closed quarantine actions"),
            }
            .map_err(|error| error.reason_code())?]
        }
        "status" => executor.status().map_err(|error| error.reason_code())?,
        _ => return Err("host_executor_arguments_denied"),
    };
    emit(&outcomes).map_err(|_| "host_executor_output_failed")
}

fn emit(outcomes: &[HostExecutorOutcome]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut locked = stdout.lock();
    serde_json::to_writer(&mut locked, outcomes)?;
    locked.write_all(b"\n")
}
