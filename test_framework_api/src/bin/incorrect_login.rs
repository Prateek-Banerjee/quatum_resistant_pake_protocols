#![allow(unused_imports)]
use qr_pake_protocol_executors::{DEFAULT_IP, DEFAULT_PORT, login};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, KemChoice::*, OcakeClient, TkClient};

#[tokio::main]
async fn main() {
    let client_id = b"This is a default pake client id";
    let another_password = b"This  some other wrong password.";

    // Create a client instance with the same incorrect password across different files
    let new_client_instance = KemAeClient::new(
        client_id.to_vec(),
        another_password.to_vec(),
        Paranoid,
    );

    // Perform login
    let _ = login::<KemAeClient>(new_client_instance, DEFAULT_IP, DEFAULT_PORT)
        .await
        .expect("Login failed");
}
