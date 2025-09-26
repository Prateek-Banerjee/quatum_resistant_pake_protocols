#![allow(unused_imports)]
use qr_pake_protocol_executors::{login, register, DEFAULT_IP, DEFAULT_PORT};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, KemChoice::*, OcakeClient, TkClient};
use std::{thread, time::Duration};

#[tokio::main]
async fn main() {
    let client_prateek = b"Prateek Banerjee is the user now";
    let client_chandan = b"Chandan Banerjee is the user now";
    let client_anunita = b"Anunita Banerjee is the user now";
    let client_password = b"This is client default password.";

    // Perform registration of Prateek
    let prateek_instance = register::<OcakeClient>(
        client_prateek,
        client_password,
        LightWeight,
        Some(Frodo),
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed for Prateek");

    // Sleep for 0.5 seconds to simulate a brief delay
    thread::sleep(Duration::from_secs_f32(0.5));

    // Perform registration of Chandan
    let chandan_instance = register::<OcakeClient>(
        client_chandan,
        client_password,
        Paranoid,
        Some(Frodo),
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed for Chandan");

    // Perform registration of Anunita
    let anunita_instance = register::<OcakeClient>(
        client_anunita,
        client_password,
        Recommended,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed for Anunita");

    // Sleep for 0.5 seconds to simulate a brief delay
    thread::sleep(Duration::from_secs_f32(0.5));

    // Start all three logins concurrently so that they are run on the same thread
    let (result_prateek, result_chandan, result_anunita) = tokio::join!(
        login::<OcakeClient>(prateek_instance, DEFAULT_IP, DEFAULT_PORT),
        login::<OcakeClient>(chandan_instance, DEFAULT_IP, DEFAULT_PORT),
        login::<OcakeClient>(anunita_instance, DEFAULT_IP, DEFAULT_PORT)
    );

    let session_key_prateek = result_prateek.expect("Login failed for Prateek");
    let session_key_chandan = result_chandan.expect("Login failed for Chandan");
    let session_key_anunita = result_anunita.expect("Login failed for Anunita");

    println!(
        "\x1b[92m\t Prateek's Session Key: {:?} \x1b[0m\n",
        session_key_prateek
    );
    println!(
        "\x1b[93m\t Chandan's Session Key: {:?} \x1b[0m\n",
        session_key_chandan
    );
    println!(
        "\x1b[94m\t Anuita's Session Key: {:?} \x1b[0m\n",
        session_key_anunita
    );
}
