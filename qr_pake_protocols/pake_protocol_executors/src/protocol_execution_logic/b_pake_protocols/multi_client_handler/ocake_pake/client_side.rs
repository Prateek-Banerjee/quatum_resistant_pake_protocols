/*
[1] Towards post-quantum secure PAKE-A tight security proof for OCAKE in the BPR model
https://eprint.iacr.org/2023/1368.pdf
*/

use crate::protocol_execution_logic::b_pake_protocols::multi_client_handler::{
    client_handler::ClientHandler, LOGIN, REGISTER,
};
use qr_pake_protocols::{
    AvailableVariants,
    KemChoice::{self, *},
    OcakeClient,
};
use serde_json::{from_slice, to_vec};
use std::{str::from_utf8, thread, time::Duration};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[async_trait::async_trait]
impl ClientHandler for OcakeClient {
    type ClientType = OcakeClient;

    async fn register_client(
        client_id: &[u8],
        client_password: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        ip: &str,
        port: &str,
    ) -> io::Result<Self::ClientType> {
        let chosen_kem: KemChoice = kem_choice.unwrap_or(Kyber);
        register_client(
            client_id,
            client_password,
            protocol_variant,
            chosen_kem,
            ip,
            port,
        )
        .await
    }

    async fn login(
        client_instance: Self::ClientType,
        ip: &str,
        port: &str,
    ) -> io::Result<[u8; 32]> {
        login(client_instance, ip, port).await
    }
}

/// Enum representing the steps in the client workflow.
///
/// # Fields:
/// - `ClientInit`: The initial step for the client.
/// - `ClientFinish`: The final step on the client's end.
/// - `Done`: Indicates completion of the client process.
#[derive(Clone, Copy, PartialEq, Debug)]
enum ClientSteps {
    ClientInit,
    ClientFinish,
    Done,
}

/// Asynchronously registers a client of the `Modified OCAKE-PAKE` protocol.
///
/// # Parameters:
/// - `client_id`: `&[u8]` - The client identifier bytes.
/// - `client_password`: `&[u8]` - The client's password bytes.
/// - `protocol_variant`: `AvailableVariants` - The chosen protocol variant.
/// - `kem_choice`: `KemChoice` - The chosen KEM.
/// - `ip: &str` - The server IP address.
/// - `port: &str` - The server port.
///
/// # Returns:
/// - `io::Result<OcakeClient>`: The resulting `OcakeClient` instance on success or an I/O error.
async fn register_client(
    client_id: &[u8],
    client_password: &[u8],
    protocol_variant: AvailableVariants,
    kem_choice: KemChoice,
    ip: &str,
    port: &str,
) -> io::Result<OcakeClient> {
    let ip_address: String = format!("{}:{}", ip, port);
    let mut stream: TcpStream = TcpStream::connect(ip_address.clone()).await?;
    println!(
        "INFO: OCAKE-PAKE client connected to server at {} for registration",
        ip_address
    );

    let ocake_client: OcakeClient = OcakeClient::new(
        client_id.to_vec(),
        client_password.to_vec(),
        protocol_variant,
        kem_choice,
    );

    // Send a prefix for registration
    let mut register_prefix = [0u8; 8];
    let register_bytes = REGISTER.as_bytes();
    register_prefix[..register_bytes.len()].copy_from_slice(register_bytes);
    stream.write_all(register_bytes).await?;
    println!("INFO: Registration prefix sent to server");

    // Perform the One-Time Client Registration by sending the client ID, password,
    // protocol_variant, and the KEM choice to the server
    // Serialize the data so that it can be sent over the network
    let serialized_data_to_be_sent: Vec<u8> = to_vec(&(
        client_id.to_vec(),
        client_password.to_vec(),
        protocol_variant,
        kem_choice,
    ))
    .unwrap();

    let mut client_message: Vec<u8> = Vec::new();
    client_message.extend((serialized_data_to_be_sent.len() as u32).to_le_bytes());
    client_message.extend(serialized_data_to_be_sent);

    // Send the message to the server
    stream.write_all(&client_message).await.unwrap();
    println!("INFO: Registration details sent to server");

    let mut server_response_buffer: [u8; 256] = [0u8; 256];
    let msg_size: usize = stream.read(&mut server_response_buffer).await?;
    let server_message: &str = from_utf8(&server_response_buffer[..msg_size]).unwrap_or("");

    if !server_message.starts_with("OK") {
        eprintln!("{}", server_message);
        return Err(io::Error::new(io::ErrorKind::Other, server_message));
    }

    println!("INFO: {}", server_message);

    Ok(ocake_client)
}

/// Asynchronously performs the client login of the `Modified OCAKE-PAKE` protocol.
///
/// # Parameters:
/// - `ocake_client`: `OcakeClient` - The client instance performing the login.
/// - `ip: &str` - The server IP address.
/// - `port: &str` - The server port.
///
/// # Returns:
/// `io::Result<[u8; 32]>` – The shared session key of client of type `[u8; 32]`.
async fn login(mut ocake_client: OcakeClient, ip: &str, port: &str) -> io::Result<[u8; 32]> {
    let ip_address: String = format!("{}:{}", ip, port);
    let mut stream: TcpStream = TcpStream::connect(ip_address.clone()).await?;
    println!(
        "INFO: OCAKE-PAKE client connected to server at {} for login",
        ip_address
    );

    let mut shared_session_key: [u8; 32] = [0u8; 32];
    let mut client_steps: ClientSteps = ClientSteps::ClientInit;

    // Prepare the client ID, kem_choice and the protocol_variant to be sent so the server can load the correct state
    let client_id: Vec<u8> = ocake_client.client_id();
    let protocol_variant: AvailableVariants = ocake_client.protocol_variant();
    let kem_choice: KemChoice = ocake_client.kem_choice();

    // Serialize the data so that it can be sent over the network
    let serialized_data_to_be_sent: Vec<u8> =
        to_vec(&(client_id, protocol_variant, kem_choice)).unwrap();
    let mut client_message: Vec<u8> = Vec::new();
    client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
    client_message.extend(serialized_data_to_be_sent);

    // Send the prefix for login
    let mut login_prefix = [0u8; 8];
    let login_bytes = LOGIN.as_bytes();
    login_prefix[..login_bytes.len()].copy_from_slice(login_bytes);
    stream.write_all(&login_prefix).await?;
    println!("INFO: Login prefix sent to server");

    // Send the the client ID, protocol variant and KEM choice to the server
    stream.write_all(&client_message).await?;
    println!("INFO: Sent the client ID, protocol variant and KEM choice for login");

    let mut server_response_buffer: [u8; 256] = [0u8; 256];
    let msg_size: usize = stream.read(&mut server_response_buffer).await?;
    let server_message: &str = from_utf8(&server_response_buffer[..msg_size]).unwrap_or("");

    if !server_message.eq("Begin") {
        eprintln!("{}", server_message);
        return Err(io::Error::new(io::ErrorKind::Other, server_message));
    }

    while client_steps != ClientSteps::Done {
        match client_steps {
            ClientSteps::ClientInit => {
                // Perform the Client_Init operation
                let (c, nonce_c) = ocake_client.client_init();
                println!("INFO: Client Init step is successful.");

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> =
                    to_vec(&(c.clone(), nonce_c.clone())).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u32).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                println!("INFO: Client Init data sent to the server");

                client_steps = ClientSteps::ClientFinish;
            }

            ClientSteps::ClientFinish => {
                // Buffer to store the incoming data
                let mut client_buffer_size: [u8; 4] = [0u8; 4];

                stream.read_exact(&mut client_buffer_size).await.unwrap();

                let server_message_size: usize = u32::from_le_bytes(client_buffer_size) as usize;
                let mut buffer: Vec<u8> = vec![0u8; server_message_size];
                stream.read_exact(&mut buffer).await.unwrap();

                // Deserialize the data into a tuple (kem_ciphertext, tag_one)
                let (kem_ciphertext, tag_one): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();
                println!("INFO: Server data received for Client Finish");

                // Perform the Client_Finish operation
                match ocake_client.client_finish(&kem_ciphertext, &tag_one) {
                    Ok((tag_two, session_key)) => {
                        println!("INFO: Client Finish step is successful.");

                        // Serialize the data so that it can be sent over the network
                        let serialized_data_to_be_sent: Vec<u8> =
                            to_vec(&(tag_two.to_vec())).unwrap();

                        let mut client_message: Vec<u8> = Vec::new();
                        client_message
                            .extend((serialized_data_to_be_sent.len() as u8).to_le_bytes());
                        client_message.extend(serialized_data_to_be_sent);

                        // Send the message to the server
                        stream.write_all(&client_message).await.unwrap();
                        println!("INFO: Client Finish data sent to the server");

                        shared_session_key = session_key;

                        client_steps = ClientSteps::Done;
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);

                        // Send explicit error message to server
                        let error_msg = b"EXPLICIT_AUTH_FAILED";
                        stream.write_all(&[error_msg.len() as u8]).await?;
                        stream.write_all(error_msg).await?;

                        let mut server_response_buffer: [u8; 256] = [0u8; 256];
                        let msg_size: usize = stream.read(&mut server_response_buffer).await?;
                        let server_message: &str =
                            from_utf8(&server_response_buffer[..msg_size]).unwrap_or("");

                        return Err(io::Error::new(io::ErrorKind::Other, server_message));
                    }
                }
            }

            _ => break,
        }
    }
    thread::sleep(Duration::from_secs_f32(0.2));

    let mut server_response_buffer: [u8; 256] = [0u8; 256];
    let msg_size: usize = stream.read(&mut server_response_buffer).await?;
    let server_message: &str = from_utf8(&server_response_buffer[..msg_size]).unwrap_or("");

    if !server_message.starts_with("OK") {
        eprintln!("{}", server_message);
        return Err(io::Error::new(io::ErrorKind::Other, server_message));
    }

    println!("INFO: {}", server_message);

    Ok(shared_session_key)
}
