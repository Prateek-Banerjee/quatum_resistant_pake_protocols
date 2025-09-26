use crate::protocol_execution_logic::b_pake_protocols::multi_client_handler::client_handler::ClientHandler;
use qr_pake_protocols::{AvailableVariants, KemChoice};
use std::io::Result;

/// Registers a client with the PAKE protocol server using the specified credentials and protocol settings.
///
/// # Type Parameters:
/// - `H: ClientHandler` - The client handler type implementing the protocol logic.
///
/// # Parameters:
/// - `client_id`: `&[u8]` - The client's identifier.
/// - `client_password`: `&[u8]` - The client's password.
/// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
/// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice only for the `Modified OCAKE-PAKE` protocol.
/// - `ip`: `&str` - The server IP address.
/// - `port`: `&str` - The server port.
///
/// # Returns:
/// - `Result<H::ClientType>` - Returns the registered client instance or an error.
pub async fn register<H: ClientHandler>(
    client_id: &[u8],
    client_password: &[u8],
    protocol_variant: AvailableVariants,
    kem_choice: Option<KemChoice>,
    ip: &str,
    port: &str,
) -> Result<H::ClientType> {
    H::register_client(
        client_id,
        client_password,
        protocol_variant,
        kem_choice,
        ip,
        port,
    )
    .await
}

/// Performs a login operation for the client and returns the session key.
///
/// # Type Parameters:
/// - `H: ClientHandler` - The client handler type implementing the protocol logic.
///
/// # Parameters:
/// - `client_instance`: `H::ClientType` - The client instance to use for login.
/// - `ip`: `&str` - The server IP address.
/// - `port`: `&str` - The server port.
///
/// # Returns:
/// - `Result<[u8; 32]>` - Returns the session key if login is successful, or an error otherwise.
pub async fn login<H: ClientHandler>(
    client_instance: H::ClientType,
    ip: &str,
    port: &str,
) -> Result<[u8; 32]> {
    H::login(client_instance, ip, port).await
}
