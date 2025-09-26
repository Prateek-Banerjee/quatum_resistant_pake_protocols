#![allow(unused_imports)]
use qr_pake_protocol_executors::{login, register, DEFAULT_IP, DEFAULT_PORT};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, KemChoice::*, OcakeClient, TkClient};
use std::{thread, time::Duration};

#[tokio::main]
async fn main() {
    let client_prateek = b"Prateek Banerjee is the user now";
    let client_chandan = b"Chandan Banerjee is the user now";
    let client_password = b"This is client default password.";

    // Perform registration of Prateek
    let prateek_instance = register::<TkClient>(
        client_prateek,
        client_password,
        Paranoid,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration of Prateek failed");

    // Perform registration of Chandan
    let chandan_instance = register::<TkClient>(
        client_chandan,
        client_password,
        Paranoid,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration of Chandan failed");

    // Sleep for 2 seconds to simulate a small delay
    thread::sleep(Duration::from_secs_f32(2.0));

    // Perform login of Chandan
    let session_key: [u8; 32] = login::<TkClient>(chandan_instance, DEFAULT_IP, DEFAULT_PORT)
        .await
        .expect("Login failed");
    println!(
        "\x1b[92m\t Chandan's Session Key: {:?} \x1b[0m\n",
        session_key
    );

    // Sleep for 5 seconds to simulate relatively longer delay
    thread::sleep(Duration::from_secs_f32(5.0));

    // Perform login of Prateek
    let session_key: [u8; 32] = login::<TkClient>(prateek_instance, DEFAULT_IP, DEFAULT_PORT)
        .await
        .expect("Login failed");
    println!(
        "\x1b[92m\t Prateek's Session Key: {:?} \x1b[0m\n",
        session_key
    );
}
