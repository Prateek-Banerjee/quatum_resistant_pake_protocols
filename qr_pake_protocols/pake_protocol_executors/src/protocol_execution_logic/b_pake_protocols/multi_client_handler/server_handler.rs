use super::storage_handler::Storage;
use std::sync::Arc;
use tokio::net::TcpStream;

/// Trait for handling server-side logic in multi-client PAKE protocols.
/// This trait defines asynchronous handlers for registration and login operations,
/// using a generic server type and a shared storage backend.
///
/// # Associated Type:
/// - `ServerType`: The type representing the server of the PAKE protocol.
///
/// # Required Methods:
/// - `registration_handler`: Handles client registration over a TCP stream.
/// - `login_handler`: Handles client login over a TCP stream.
#[async_trait::async_trait]
pub trait ServerHandler: Send + Sync + 'static {
    type ServerType: Send + Sync + 'static;

    async fn registration_handler(
        socket: TcpStream,
        storage: Arc<dyn Storage<Self::ServerType> + Send + Sync>,
    );
    async fn login_handler(
        socket: TcpStream,
        storage: Arc<dyn Storage<Self::ServerType> + Send + Sync>,
        login_threshold: usize,
        login_window: u64,
        resp_timeout: u64,
    );
}
