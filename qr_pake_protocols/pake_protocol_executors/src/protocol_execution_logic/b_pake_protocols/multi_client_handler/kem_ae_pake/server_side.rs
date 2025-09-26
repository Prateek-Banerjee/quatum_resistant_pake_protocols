/*
[1] Efficient Asymmetric PAKE Compiler from KEM and AE
https://eprint.iacr.org/2024/1400
*/

use crate::protocol_execution_logic::b_pake_protocols::multi_client_handler::{
    server_handler::ServerHandler, storage_handler::Storage,
};
use qr_pake_protocols::{to_human_readable, AvailableVariants, KemAeServer};
use serde_json::{from_slice, to_vec};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

#[async_trait::async_trait]
impl ServerHandler for KemAeServer {
    type ServerType = KemAeServer;

    async fn registration_handler(
        socket: TcpStream,
        storage: Arc<dyn Storage<Self::ServerType> + Send + Sync>,
    ) {
        registration_handler(socket, storage).await;
    }

    async fn login_handler(
        socket: TcpStream,
        storage: Arc<dyn Storage<Self::ServerType> + Send + Sync>,
        login_threshold: usize,
        login_window: u64,
        resp_timeout: u64,
    ) {
        login_handler(socket, storage, login_threshold, login_window, resp_timeout).await;
    }
}

/// Handles the registration process for a client over a TCP stream for `KEM-AE-PAKE`
///
/// # Parameters:
/// - `socket`: `TcpStream,` - The TCP stream representing the client connection.
/// - `storage`: `Arc<dyn Storage<Self::ServerType> + Send + Sync>,` - Shared storage backend for managing server state.
async fn registration_handler(
    mut socket: TcpStream,
    storage: Arc<dyn Storage<KemAeServer> + Send + Sync>,
) {
    // Buffer to store the incoming data
    let mut server_buffer_size: [u8; 4] = [0u8; 4];
    if socket.read_exact(&mut server_buffer_size).await.is_err() {
        return;
    }
    let client_message_size: usize = u32::from_le_bytes(server_buffer_size) as usize;
    let mut buffer: Vec<u8> = vec![0u8; client_message_size];
    if socket.read_exact(&mut buffer).await.is_err() {
        return;
    }

    // Deserialize the data into a tuple (client_id, rw, initial_kem_public_key, protocol_variant)
    let (client_id, rw, initial_kem_public_key, protocol_variant): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        AvailableVariants,
    ) = from_slice(&buffer).unwrap();
    println!(
        "INFO: Client data for {} received for registration",
        to_human_readable(&client_id)
    );

    // Before registering, check if the client with the chosen variant already exists
    let client_already_registered = storage.client_exists(&client_id, protocol_variant, None);

    match client_already_registered {
        Ok(true) => {
            eprintln!("WARNING: Client ID {} with variant {} is already registered. Skipping registration.", to_human_readable(&client_id), to_human_readable(&(protocol_variant.to_bytes())));
            let _ = socket.write_all(b"WARNING: The Client ID with the chosen variant is already registered. Skipping registration.").await;
        }
        Ok(false) => {
            // In case client is not already registered
            let mut kemae_server: KemAeServer = KemAeServer::new(protocol_variant);

            // One-Time Client Registration for the current client
            kemae_server.accept_registration(client_id.clone(), rw, initial_kem_public_key);

            // Store the server instance in the storage
            storage
                .insert_server_instance(client_id.clone(), protocol_variant, None, &kemae_server)
                .expect("ERROR: Inserting server state in storage failed");

            println!(
                "INFO: Registration of client {} is successful.",
                to_human_readable(&client_id)
            );

            let _ = socket
                .write_all(b"OK: Client registration is successful.")
                .await;
        }
        Err(e) => {
            eprintln!(
                "ERROR: Existence checking from storage for client {} failed: {}",
                to_human_readable(&client_id),
                e
            );
            return;
        }
    }
}

/// Handles the login process for a client over a TCP stream for `KEM-AE-PAKE`
///
/// # Parameters:
/// - `socket`: `TcpStream,` - The TCP stream representing the client connection.
/// - `storage`: `Arc<dyn Storage<Self::ServerType> + Send + Sync>,` - Shared storage backend for managing server state.
/// - `login_threshold`: `usize` - Maximum number of incorrect login attempts allowed.
/// - `login_window`: `u64` - Time frame within which the `login_threshold` is applicable.
/// - `resp_timeout`: `u64` - Timeout until which the server waits to receive a response from a client.
async fn login_handler(
    mut socket: TcpStream,
    storage: Arc<dyn Storage<KemAeServer> + Send + Sync>,
    login_threshold: usize,
    login_window: u64,
    resp_timeout: u64,
) {
    let mut server_buffer_size: [u8; 2] = [0u8; 2];
    if socket.read_exact(&mut server_buffer_size).await.is_err() {
        return;
    }
    let client_message_size: usize = u16::from_le_bytes(server_buffer_size) as usize;
    let mut buffer: Vec<u8> = vec![0u8; client_message_size];
    if socket.read_exact(&mut buffer).await.is_err() {
        return;
    }

    // Receive the client_id and the protocol_variant for login
    let (client_id, protocol_variant): (Vec<u8>, AvailableVariants) = from_slice(&buffer).unwrap();
    println!(
        "INFO: Client ID {} and protocol variant {} received for login",
        to_human_readable(&client_id),
        to_human_readable(&(protocol_variant.to_bytes()))
    );

    // Check if the client with the chosen variant exists or not before login
    let exists: bool = storage
        .client_exists(&client_id, protocol_variant, None)
        .expect(
            format!(
                "ERROR: Existence checking from storage for client {} failed",
                to_human_readable(&client_id)
            )
            .as_str(),
        );

    if !exists {
        eprintln!(
            "ERROR: Client ID: {} with variant {} is not registered. Cannot login.",
            to_human_readable(&client_id),
            to_human_readable(&(protocol_variant.to_bytes()))
        );
        let _ = socket.write_all(b"ERROR: The Client ID with the chosen variant is not registered. So, the client cannot login.").await;
        return;
    }

    // Check once if client is already blocked or not
    if storage
        .is_client_blocked(&client_id, protocol_variant, None)
        .unwrap_or(false)
    {
        eprintln!(
            "ERROR: Client ID: {} with variant {} is blocked due to too many incorrect login attempts.",
            to_human_readable(&client_id),
            to_human_readable(&(protocol_variant.to_bytes()))
        );
        let _ = socket
            .write_all(b"ERROR: The Client ID with the chosen variant is already blocked due to multiple consecutive incorrect login attempts.")
            .await;
        return;
    }

    // Get the server state from the storage which was stored after client registration
    let mut kemae_server: KemAeServer = match storage
        .get_stored_server_instance(client_id.clone(), protocol_variant, None)
        .expect("ERROR: Retrieving server state from storage failed.")
    {
        Some(server_instance) => server_instance,
        None => return,
    };

    let _ = socket.write_all(b"Begin").await;

    let mut server_buffer_size: [u8; 2] = [0u8; 2];
    socket.read_exact(&mut server_buffer_size).await.unwrap();

    let client_message_size = u16::from_le_bytes(server_buffer_size) as usize;
    let mut buffer = vec![0u8; client_message_size];
    socket.read_exact(&mut buffer).await.unwrap();

    // Deserialize the data into a tuple (c_1, nonce_c_1)
    let (c_1, nonce_c_1): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();
    println!(
        "INFO: Client data for {} received for Server Resp",
        to_human_readable(&client_id)
    );

    // Perform the server_resp operation
    let (c_2, nonce_c_2, psi, nonce_psi) = kemae_server.server_resp(c_1, &nonce_c_1);
    println!(
        "INFO: Server Resp step for client {} is successful.",
        to_human_readable(&client_id)
    );

    let serialized_data_to_be_sent: Vec<u8> = to_vec(&(
        c_2.clone(),
        nonce_c_2.clone(),
        psi.clone(),
        nonce_psi.clone(),
    ))
    .unwrap();

    // Send the message to the client
    let mut server_message: Vec<u8> = Vec::new();
    server_message.extend((serialized_data_to_be_sent.len() as u32).to_le_bytes());
    server_message.extend(serialized_data_to_be_sent);
    if socket.write_all(&server_message).await.is_err() {
        return;
    }
    println!(
        "INFO: Server Resp data sent to the client {}",
        to_human_readable(&client_id)
    );

    let mut server_buffer_size: [u8; 1] = [0u8; 1];

    // Read the length prefix with timeout
    let read_len_result = timeout(
        Duration::from_secs(resp_timeout),
        socket.read_exact(&mut server_buffer_size),
    )
    .await;

    if read_len_result.is_err() {
        // Timeout occurred while waiting for length prefix
        handle_incorrect_login_attempt(
            &mut socket,
            &storage,
            &client_id,
            protocol_variant,
            login_window,
            login_threshold,
        )
        .await;
        return;
    }

    let client_message_size: usize = u8::from_le_bytes(server_buffer_size) as usize;
    let mut buffer: Vec<u8> = vec![0u8; client_message_size];

    // Read the actual message with timeout
    let read_msg_result = timeout(
        Duration::from_secs(resp_timeout),
        socket.read_exact(&mut buffer),
    )
    .await;

    if read_msg_result.is_err() {
        // Timeout occurred while waiting for actual message
        handle_incorrect_login_attempt(
            &mut socket,
            &storage,
            &client_id,
            protocol_variant,
            login_window,
            login_threshold,
        )
        .await;
        return;
    }

    // Check if client sent explicit error message instead of sigma
    if &buffer == b"EXPLICIT_AUTH_FAILED" {
        // Record as incorrect login attempt
        handle_incorrect_login_attempt(
            &mut socket,
            &storage,
            &client_id,
            protocol_variant,
            login_window,
            login_threshold,
        )
        .await;
        return;
    }

    // Deserialize the data into sigma
    let sigma: Vec<u8> = from_slice(&buffer).unwrap();
    println!(
        "INFO: Client data for {} received for Server Finish",
        to_human_readable(&client_id)
    );

    // Perform the server finish operation
    match kemae_server.server_finish(sigma) {
        Ok(_shared_session_key) => {
            println!(
                "INFO: Server Finish step for client {} is successful.",
                to_human_readable(&client_id)
            );
            // Fetch the current incorrect login attempt count
            let current_count: usize = storage
                .get_incorrect_login_attempts_count(&client_id, protocol_variant, None)
                .unwrap_or(0);

            if current_count > 0 {
                // Reset failed login attempts in case of correct password
                let _ = storage.reset_incorrect_login_attempts(&client_id, protocol_variant, None);
                println!(
                    "INFO: Counter reset to 0 for client ID {} with protocol variant {} for correct login details",
                    to_human_readable(&client_id),
                    to_human_readable(&(protocol_variant.to_bytes()))
                );
            }
            let _ = socket.write_all(b"OK: Client login is successful.").await;
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            handle_incorrect_login_attempt(
                &mut socket,
                &storage,
                &client_id,
                protocol_variant,
                login_window,
                login_threshold,
            )
            .await;
            return;
        }
    }
}

async fn handle_incorrect_login_attempt(
    socket: &mut TcpStream,
    storage: &Arc<dyn Storage<KemAeServer> + Send + Sync>,
    client_id: &[u8],
    protocol_variant: AvailableVariants,
    login_window: u64,
    login_threshold: usize,
) {
    let count: usize = storage
        .record_incorrect_login_attempt(&client_id, protocol_variant, None, login_window)
        .unwrap_or(0);

    if count == login_threshold {
        let _ = storage.block_client(&client_id, protocol_variant, None);
        eprintln!(
            "ERROR: Client ID: {} with variant {} has been blocked after {} consecutive incorrect login attempts.",
            to_human_readable(&client_id),
            to_human_readable(&(protocol_variant.to_bytes())),
            count
        );
        let msg: String = format!("ERROR: The Client ID with the chosen variant is blocked due to {} consecutive incorrect login attempts.", count);
        let _ = socket.write_all(msg.as_bytes()).await;
    } else {
        eprintln!(
            "ERROR: Incorrect password for client {} (variant {}). Attempt {}/{}.",
            to_human_readable(&client_id),
            to_human_readable(&(protocol_variant.to_bytes())),
            count,
            login_threshold
        );
        let msg: String = format!("ERROR: The Client ID with the chosen variant used an incorrect password. Attempts used {}/{}", count, login_threshold);
        let _ = socket.write_all(msg.as_bytes()).await;
    }
}
