//! FireWhal IPC router entry point.
use firewhal_core::DEFAULT_IPC_ENDPOINT;
use firewhal_ipc::run_router;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_router(DEFAULT_IPC_ENDPOINT.to_string(), true).await
}
