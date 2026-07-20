//! Janus approval, lifecycle, migration, and recovery administration process.

#![forbid(unsafe_code)]

use anyhow::Result;
use janus_core::RuntimePlane;

#[tokio::main]
async fn main() -> Result<()> {
    janusd::run_for_plane(Some(RuntimePlane::Admin)).await
}
