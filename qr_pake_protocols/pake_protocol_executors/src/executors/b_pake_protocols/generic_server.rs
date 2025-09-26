use crate::protocol_execution_logic::b_pake_protocols::multi_client_handler::{
    server_handler::ServerHandler, storage_handler::Storage, LOGIN, REGISTER,
};
use std::{any::type_name, io::Result, sync::Arc};
use tokio::{io::AsyncReadExt, net::TcpListener, spawn};

/// Starts a multi-client PAKE protocol server and listens for incoming registration and login requests.
///
/// This function binds a TCP listener to the specified IP address and port, then continuously accepts
/// incoming connections. For each connection, it reads a request prefix to determine whether the client
/// is attempting to register or login, and dispatches the request to the appropriate handler method
/// defined by the `ServerHandler` trait.
///
/// # Type Parameters:
/// - `H: ServerHandler` - The server handler type implementing the protocol logic.
///
/// # Parameters:
/// - `storage`: `Arc<dyn Storage<H::ServerType> + Send + Sync>` - Shared storage backend for server state.
/// - `ip`: `&str` - The IP address to bind the server to.
/// - `port`: `&str` - The port to bind the server to.
/// - `login_threshold`: `usize` - Maximum number of incorrect login attempts allowed.
/// - `login_window`: `u64` - Time frame within which the `login_threshold` is applicable.
/// - `resp_timeout`: `u64` - Timeout until which the server waits to receive a response from a client.
///
/// # Returns:
/// - `Result<()>` - Returns `Ok(())` if the server starts successfully, or an error otherwise.
pub async fn start_server<H: ServerHandler>(
    storage: Arc<dyn Storage<H::ServerType> + Send + Sync>,
    ip: &str,
    port: &str,
    login_threshold: usize,
    login_window: u64,
    resp_timeout: u64,
) -> Result<()> {
    let ip_address: String = format!("{}:{}", ip, port);
    let listener: TcpListener = TcpListener::bind(ip_address.clone()).await?;
    let full_type = type_name::<H>();
    let server_type = full_type.rsplit("::").next().unwrap_or(full_type);
    println!("INFO: {} listening to address {}", server_type, ip_address);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let storage = Arc::clone(&storage);
        spawn(async move {
            let mut prefix_buf = [0u8; 8];
            if socket.read_exact(&mut prefix_buf).await.is_err() {
                return;
            }
            let prefix_str = std::str::from_utf8(&prefix_buf)
                .unwrap_or("")
                .trim_end_matches(char::from(0));
            if prefix_str == REGISTER {
                H::registration_handler(socket, storage).await;
            } else if prefix_str == LOGIN {
                H::login_handler(socket, storage, login_threshold, login_window, resp_timeout)
                    .await;
            } else {
                eprintln!("ERROR: Unknown request type received: {}", prefix_str);
                return;
            }
        });
    }
}
