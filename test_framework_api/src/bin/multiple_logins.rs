#![allow(unused_imports)]
use qr_pake_protocol_executors::{DEFAULT_IP, DEFAULT_PORT, login, register};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, KemChoice::*, OcakeClient, TkClient};
use std::{thread, time::Duration};

#[tokio::main]
async fn main() {
    let client_id = b"This is a default pake client id";
    let client_password = b"This is client default password.";

    // Perform registration
    let client_instance = register::<KemAeClient>(
        client_id,
        client_password,
        LightWeight,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed");

    // Perform first login
    let session_key: [u8; 32] =
        login::<KemAeClient>(client_instance.clone(), DEFAULT_IP, DEFAULT_PORT)
            .await
            .expect("Login failed");
    println!(
        "\x1b[92m\t Client's Session Key for 1st login: {:?} \x1b[0m\n",
        session_key
    );

    // Sleep for 10 seconds to simulate long delay
    thread::sleep(Duration::from_secs_f32(10.0));

    // Perform second login
    let session_key: [u8; 32] =
        login::<KemAeClient>(client_instance.clone(), DEFAULT_IP, DEFAULT_PORT)
            .await
            .expect("Login failed");
    println!(
        "\x1b[92m\t Client's Session Key for 2nd login: {:?} \x1b[0m\n",
        session_key
    );

    // Sleep for 1 second to simulate a very short delay
    thread::sleep(Duration::from_secs_f32(1.0));

    // Perform third login
    let session_key: [u8; 32] = login::<KemAeClient>(client_instance, DEFAULT_IP, DEFAULT_PORT)
        .await
        .expect("Login failed");
    println!(
        "\x1b[92m\t Client's Session Key for 3rd login: {:?} \x1b[0m\n",
        session_key
    );
}
