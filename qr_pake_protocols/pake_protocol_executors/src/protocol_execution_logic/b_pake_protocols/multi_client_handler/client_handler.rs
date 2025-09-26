use qr_pake_protocols::{AvailableVariants, KemChoice};
use std::io::Result;

/// Trait for handling client-side logic of the PAKE protocols.
/// This trait defines asynchronous methods for client registration and login operations,
/// supporting protocol variants and optional KEM choices.
///
/// # Associated Type:
/// - `ClientType`: The type representing the client of the PAKE protocol.
///
/// # Required Methods:
/// - `register_client`: Registers a client with the server.
/// - `login`: Performs a login operation for the client and returns the session key of the client.
#[async_trait::async_trait]
pub trait ClientHandler: Send + Sync + 'static {
    type ClientType: Send + Sync + 'static;

    async fn register_client(
        client_id: &[u8],
        client_password: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        ip: &str,
        port: &str,
    ) -> Result<Self::ClientType>;

    async fn login(client_instance: Self::ClientType, ip: &str, port: &str) -> Result<[u8; 32]>;
}
