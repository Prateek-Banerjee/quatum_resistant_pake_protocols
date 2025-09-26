#![allow(unused_imports)]
use qr_pake_protocol_executors::{DEFAULT_IP, DEFAULT_PORT, register};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, KemChoice::*, OcakeClient, TkClient};

#[tokio::main]
async fn main() {
    let client_id = b"This is a default pake client id";
    let client_password = b"This is client default password.";

    // Perform registration
    let _ = register::<KemAeClient>(
        client_id,
        client_password,
        Paranoid,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed");
}
