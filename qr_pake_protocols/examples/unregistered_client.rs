#![allow(unused_imports)]
use qr_pake_protocol_executors::{login, register, DEFAULT_IP, DEFAULT_PORT};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, OcakeClient, TkClient};

#[tokio::main]
async fn main() {
    let client_id = b"This is a default pake client id";
    let client_password = b"This is client default password.";

    // Not performing registration but still creating a client instance
    let client_instance =
        KemAeClient::new(client_id.to_vec(), client_password.to_vec(), LightWeight);

    // Perform login for an unregistered clieent
    let _ = login::<KemAeClient>(client_instance, DEFAULT_IP, DEFAULT_PORT)
        .await
        .expect("Login failed");
}
