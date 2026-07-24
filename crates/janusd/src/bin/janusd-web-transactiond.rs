//! Private managed-service web transaction boundary.

#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args_os().len() != 1 {
        anyhow::bail!(
            "janusd-web-transactiond accepts no arguments reason_code=web_transaction_arguments_denied value_returned=false"
        );
    }
    janusd::run_web_transaction_service().await
}
