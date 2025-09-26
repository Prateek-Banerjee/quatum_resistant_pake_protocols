#![allow(unused_imports)]
use qr_pake_protocol_executors::{login, register, DEFAULT_IP, DEFAULT_PORT};
use qr_pake_protocols::{AvailableVariants::*, KemAeClient, KemChoice::*, OcakeClient, TkClient};
use std::{thread, time::Duration};
use tokio::spawn;

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() {
    let client_prateek = b"Prateek Banerjee is the user now";
    let client_chandan = b"Chandan Banerjee is the user now";
    let client_anunita = b"Anunita Banerjee is the user now";
    let client_password = b"This is client default password.";

    // Perform registration of Prateek
    let prateek_instance = register::<TkClient>(
        client_prateek,
        client_password,
        LightWeight,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed for Prateek");

    // Sleep for 0.5 seconds to simulate a brief delay
    thread::sleep(Duration::from_secs_f32(0.5));

    // Perform registration of Chandan
    let chandan_instance = register::<TkClient>(
        client_chandan,
        client_password,
        Recommended,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed for Chandan");

    // Perform registration of Anunita
    let anunita_instance = register::<TkClient>(
        client_anunita,
        client_password,
        Paranoid,
        None,
        DEFAULT_IP,
        DEFAULT_PORT,
    )
    .await
    .expect("Registration failed for Anunita");

    // Sleep for 0.5 seconds to simulate a brief delay
    thread::sleep(Duration::from_secs_f32(0.5));

    // Create three task handlers for each client
    let prateek_handler =
        spawn(async move { login::<TkClient>(prateek_instance, DEFAULT_IP, DEFAULT_PORT).await });
    let chandan_handler =
        spawn(async move { login::<TkClient>(chandan_instance, DEFAULT_IP, DEFAULT_PORT).await });
    let anunita_handler =
        spawn(async move { login::<TkClient>(anunita_instance, DEFAULT_IP, DEFAULT_PORT).await });

    // Start all three handlers concurrently , but in this case they should be run on different (worker) threads
    let (result_prateek, result_chandan, result_anunita) =
        tokio::join!(prateek_handler, chandan_handler, anunita_handler);

    let session_key_prateek = result_prateek.unwrap().expect("Login failed for Prateek");
    let session_key_chandan = result_chandan.unwrap().expect("Login failed for Chandan");
    let session_key_anunita = result_anunita.unwrap().expect("Login failed for Anunita");

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
