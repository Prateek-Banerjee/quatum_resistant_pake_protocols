/*
[1] A Generic Construction of Tightly Secure Password-based Authenticated Key Exchange
https://eprint.iacr.org/2023/1334
*/

use crate::protocol_execution_logic::b_pake_protocols::multi_client_handler::{
    client_handler::ClientHandler, LOGIN, REGISTER,
};
use qr_pake_protocols::{AvailableVariants, KemChoice, TkClient};
use serde_json::{from_slice, to_vec};
use sha2::{digest::Digest, Sha256};
use std::{str::from_utf8, thread, time::Duration};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[async_trait::async_trait]
impl ClientHandler for TkClient {
    type ClientType = TkClient;

    async fn register_client(
        client_id: &[u8],
        client_password: &[u8],
        protocol_variant: AvailableVariants,
        _kem_choice: Option<KemChoice>,
        ip: &str,
        port: &str,
    ) -> io::Result<Self::ClientType> {
        register_client(client_id, client_password, protocol_variant, ip, port).await
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
/// - `ClientTerInit`: The final step of the PAKE protocol on the client's end.
/// - `ExplicitAuth`: Explicit Authentication step.
/// - `Done`: Indicates completion of the client process.
#[derive(Clone, Copy, PartialEq, Debug)]
enum ClientSteps {
    ClientInit,
    ClientTerInit,
    ExplicitAuth,
    Done,
}

/// Asynchronously registers a client of the `TK-PAKE` protocol.
///
/// # Parameters:
/// - `client_id`: `&[u8]` - The client identifier bytes.
/// - `client_password`: `&[u8]` - The client's password bytes.
/// - `protocol_variant`: `AvailableVariants` - The chosen protocol variant.
/// - `ip: &str` - The server IP address.
/// - `port: &str` - The server port.
///
/// # Returns:
/// - `io::Result<TkClient>`: The resulting `TkClient` instance on success or an I/O error.
async fn register_client(
    client_id: &[u8],
    client_password: &[u8],
    protocol_variant: AvailableVariants,
    ip: &str,
    port: &str,
) -> io::Result<TkClient> {
    let ip_address: String = format!("{}:{}", ip, port);
    let mut stream: TcpStream = TcpStream::connect(ip_address.clone()).await?;
    println!(
        "INFO: TK-PAKE client connected to server at {} for registration",
        ip_address
    );

    let tk_client: TkClient = TkClient::new(
        client_id.to_vec(),
        client_password.to_vec(),
        protocol_variant,
    );

    // Send a prefix for registration
    let mut register_prefix = [0u8; 8];
    let register_bytes = REGISTER.as_bytes();
    register_prefix[..register_bytes.len()].copy_from_slice(register_bytes);
    stream.write_all(register_bytes).await?;
    println!("INFO: Registration prefix sent to server");

    // Perform the One-Time Client Registration by sending the
    // client ID, password and the protocol_variant to the server
    // Serialize the data so that it can be sent over the network
    let serialized_data_to_be_sent: Vec<u8> = to_vec(&(
        client_id.to_vec(),
        client_password.to_vec(),
        protocol_variant,
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

    Ok(tk_client)
}

/// Asynchronously performs the client login of the `TK-PAKE` protocol.
///
/// # Parameters:
/// - `tk_client`: `TkClient` - The client instance performing the login.
/// - `ip: &str` - The server IP address.
/// - `port: &str` - The server port.
///
/// # Returns:
/// `io::Result<[u8; 32]>` – The shared session key of client of type `[u8; 32]`.
async fn login(mut tk_client: TkClient, ip: &str, port: &str) -> io::Result<[u8; 32]> {
    let ip_address: String = format!("{}:{}", ip, port);
    let mut stream: TcpStream = TcpStream::connect(ip_address.clone()).await?;
    println!(
        "INFO: TK-PAKE client connected to server at {} for login",
        ip_address
    );

    let mut shared_session_key: [u8; 32] = [0_u8; 32];
    let mut client_steps: ClientSteps = ClientSteps::ClientInit;

    // Prepare the client ID, password and the protocol_variant to be sent so the server can load the correct state
    let client_id: Vec<u8> = tk_client.client_id();
    let protocol_variant: AvailableVariants = tk_client.protocol_variant();
    // let client_password: Vec<u8> = tk_client.client_password();

    // Serialize the data so that it can be sent over the network
    let serialized_data_to_be_sent: Vec<u8> = to_vec(&(client_id, protocol_variant)).unwrap();
    let mut client_message: Vec<u8> = Vec::new();
    client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
    client_message.extend(serialized_data_to_be_sent);

    // Send the prefix for login
    let mut login_prefix = [0u8; 8];
    let login_bytes = LOGIN.as_bytes();
    login_prefix[..login_bytes.len()].copy_from_slice(login_bytes);
    stream.write_all(&login_prefix).await?;
    println!("INFO: Login prefix sent to server");

    // Send the client ID and the protocol variant to the server
    stream.write_all(&client_message).await?;
    println!("INFO: Sent the client ID and the protocol variant for login");

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
                let (c_1, nonce_c_1) = tk_client.client_init();
                println!("INFO: Client Init step is successful.");

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> =
                    to_vec(&(c_1.clone(), nonce_c_1.clone())).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                println!("INFO: Client Init data sent to the server");

                client_steps = ClientSteps::ClientTerInit;
            }
            ClientSteps::ClientTerInit => {
                // Buffer to store the incoming data
                let mut fixed_client_buffer_size: [u8; 2] = [0u8; 2];

                stream
                    .read_exact(&mut fixed_client_buffer_size)
                    .await
                    .unwrap();
                let server_message_size: usize =
                    u16::from_le_bytes(fixed_client_buffer_size) as usize;
                let mut buffer: Vec<u8> = vec![0u8; server_message_size];
                stream.read_exact(&mut buffer).await.unwrap();

                // Deserialize the data into the (c_2, nonce_c_2)
                let (c_2, nonce_c_2): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();
                println!("INFO: Server data received for Client Ter Init");

                // Perform the Client_Ter_Init operation
                shared_session_key = tk_client.client_ter_init(&c_2, &nonce_c_2);
                println!("INFO: Client Ter Init step is successful.");

                // Generate the explicit authentication details
                let sk_digest: [u8; 32] = get_sk_digest(&shared_session_key);

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> = to_vec(&(sk_digest.to_vec())).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u8).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                println!("INFO: Explicit Authentication data sent to the server");

                client_steps = ClientSteps::ExplicitAuth;
            }
            ClientSteps::ExplicitAuth => {
                let mut server_response_buffer: [u8; 256] = [0u8; 256];
                let msg_size: usize = stream.read(&mut server_response_buffer).await?;
                let server_message: &str =
                    from_utf8(&server_response_buffer[..msg_size]).unwrap_or("");

                if !server_message.starts_with("OK") {
                    eprintln!("{}", server_message);
                    return Err(io::Error::new(io::ErrorKind::Other, server_message));
                } else {
                    println!("INFO: {}", server_message);
                    client_steps = ClientSteps::Done
                }
            }
            _ => break,
        }
    }
    thread::sleep(Duration::from_secs_f32(0.2));

    Ok(shared_session_key)
}

fn get_sk_digest(session_key: &[u8]) -> [u8; 32] {
    let mut hash_func = Sha256::new();
    hash_func.update(session_key);

    let sk_digest: [u8; 32] = hash_func.finalize().into();

    sk_digest
}
