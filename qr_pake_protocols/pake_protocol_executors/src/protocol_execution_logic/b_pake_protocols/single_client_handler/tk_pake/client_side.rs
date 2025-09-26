/*
[1] A Generic Construction of Tightly Secure Password-based Authenticated Key Exchange
https://eprint.iacr.org/2023/1334
*/

use qr_pake_protocols::{AvailableVariants, TkClient};
use serde_json::{from_slice, to_vec};
use sha2::{digest::Digest, Sha256};
use std::{
    io::Error,
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Clone, Copy, PartialEq, Debug)]
enum ClientSteps {
    ClientInit,
    ClientTerInit,
    Done,
}

pub async fn tk_pake_register_client(
    client_id: &[u8],
    client_password: &[u8],
    protocol_variant: AvailableVariants,
) -> io::Result<TkClient> {
    let mut stream: TcpStream = TcpStream::connect("127.0.0.1:8080").await?;

    let tk_client: TkClient = TkClient::new(
        client_id.to_vec(),
        client_password.to_vec(),
        protocol_variant,
    );

    // Perform the One-Time Client Registration by sending the
    // client ID and password to the server
    // Serialize the data so that it can be sent over the network
    let serialized_data_to_be_sent: Vec<u8> =
        to_vec(&(client_id.to_vec(), client_password.to_vec())).unwrap();

    let mut client_message: Vec<u8> = Vec::new();
    client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
    client_message.extend(serialized_data_to_be_sent);

    // Send the message to the server
    stream.write_all(&client_message).await.unwrap();

    Ok(tk_client)
}

pub async fn tk_pake_client_login(mut tk_client: TkClient) -> Result<(f32, usize), Error> {
    let mut total_client_time: f32 = 0.0;
    let mut communication_cost: usize = 0;

    let mut stream: TcpStream = TcpStream::connect("127.0.0.1:8080").await?;
    let mut client_steps: ClientSteps = ClientSteps::ClientInit;

    while client_steps != ClientSteps::Done {
        match client_steps {
            ClientSteps::ClientInit => {
                // Start the timer
                let client_timer: Instant = Instant::now();

                // Perform the Client_Init operation
                let (c_1, nonce_c_1) = tk_client.client_init();

                total_client_time += client_timer.elapsed().as_secs_f32();

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> =
                    to_vec(&(c_1.clone(), nonce_c_1.clone())).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                communication_cost += c_1.len() + nonce_c_1.len();

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

                // Deserialize the data into the ciphertext and nonce
                let (c_2, nonce_c_2): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();

                // Start the timer
                let client_timer: Instant = Instant::now();

                // Perform the Client_Ter_Init operation
                let _ = tk_client.client_ter_init(&c_2, &nonce_c_2);

                total_client_time += client_timer.elapsed().as_secs_f32();

                client_steps = ClientSteps::Done;
            }
            _ => break,
        }
    }
    thread::sleep(Duration::from_secs_f32(0.2));

    Ok((total_client_time, communication_cost))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum ClientStepsWithAuth {
    ClientInit,
    ClientTerInit,
    ClientAuth,
    Done,
}

pub async fn tk_pake_client_login_with_auth(
    mut tk_client: TkClient,
) -> Result<(f32, usize), Error> {
    let mut total_client_time: f32 = 0.0;
    let mut communication_cost: usize = 0;
    let mut shared_session_key: [u8; 32] = [0_u8; 32];

    let mut stream: TcpStream = TcpStream::connect("127.0.0.1:8080").await?;
    let mut client_steps: ClientStepsWithAuth = ClientStepsWithAuth::ClientInit;

    while client_steps != ClientStepsWithAuth::Done {
        match client_steps {
            ClientStepsWithAuth::ClientInit => {
                // Start the timer
                let client_timer: Instant = Instant::now();

                // Perform the Client_Init operation
                let (c_1, nonce_c_1) = tk_client.client_init();

                total_client_time += client_timer.elapsed().as_secs_f32();

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> =
                    to_vec(&(c_1.clone(), nonce_c_1.clone())).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                communication_cost += c_1.len() + nonce_c_1.len();

                client_steps = ClientStepsWithAuth::ClientTerInit;
            }
            ClientStepsWithAuth::ClientTerInit => {
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

                // Deserialize the data into the ciphertext and nonce
                let (c_2, nonce_c_2): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();

                // Start the timer
                let client_timer: Instant = Instant::now();

                // Perform the Client_Ter_Init operation
                shared_session_key = tk_client.client_ter_init(&c_2, &nonce_c_2);

                total_client_time += client_timer.elapsed().as_secs_f32();

                client_steps = ClientStepsWithAuth::ClientAuth;
            }
            ClientStepsWithAuth::ClientAuth => {
                // Start the timer
                let client_timer: Instant = Instant::now();

                let mut hash_func = Sha256::new();
                hash_func.update(shared_session_key);

                let sk_digest: [u8; 32] = hash_func.finalize().into();

                total_client_time += client_timer.elapsed().as_secs_f32();

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> = to_vec(&(sk_digest.to_vec())).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                communication_cost += sk_digest.len();

                client_steps = ClientStepsWithAuth::Done;
            }
            _ => break,
        }
    }
    thread::sleep(Duration::from_secs_f32(0.2));

    Ok((total_client_time, communication_cost))
}
