#![allow(unused_imports)]
use qr_pake_protocol_executors::{DEFAULT_IP, DEFAULT_PORT, login};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, KemChoice::*, OcakeClient, TkClient};

#[tokio::main]
async fn main() {
    let client_id = b"This is a default pake client id";
    let client_password = b"This is client default password.";

    // Just create a client instance which is already registered
    let client_instance = KemAeClient::new(
        client_id.to_vec(),
        client_password.to_vec(),
        Paranoid,
    );

    // Perform login
    let session_key: [u8; 32] = login::<KemAeClient>(client_instance, DEFAULT_IP, DEFAULT_PORT)
        .await
        .expect("Login failed");
    println!(
        "\x1b[92m\t Client's Session Key: {:?} \x1b[0m\n",
        session_key
    );
}
