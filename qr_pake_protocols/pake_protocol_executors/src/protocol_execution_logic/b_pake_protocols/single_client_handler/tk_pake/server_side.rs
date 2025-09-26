/*
[1] A Generic Construction of Tightly Secure Password-based Authenticated Key Exchange
https://eprint.iacr.org/2023/1334
*/

use qr_pake_protocols::{AvailableVariants, TkServer};
use serde_json::{from_slice, to_vec};
use sha2::{digest::Digest, Sha256};
use std::{io::Error, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Clone, Copy, PartialEq, Debug)]
enum ServerSteps {
    ServerResp,
    Done,
}

pub async fn tk_pake_accept_client_registration(
    protocol_variant: AvailableVariants,
) -> Result<TkServer, Error> {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:8080").await?;

    let mut tk_server: TkServer = TkServer::new(protocol_variant);

    if let Ok((mut socket, _)) = listener.accept().await {
        // Buffer to store the incoming data
        let mut server_buffer_size: [u8; 2] = [0u8; 2];

        // Read the data received in the buffer
        socket.read_exact(&mut server_buffer_size).await.unwrap();

        let client_message_size: usize = u16::from_le_bytes(server_buffer_size) as usize;
        let mut buffer: Vec<u8> = vec![0u8; client_message_size];
        socket.read_exact(&mut buffer).await.unwrap();

        // Deserialize the data into a tuple (client_id, client_password)
        let (client_id, client_password): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();

        // One-Time Client Registration
        tk_server.accept_registration(client_id, client_password);
    }

    Ok(tk_server)
}

pub async fn tk_pake_allow_client_login(tk_server: TkServer) -> Result<(f32, usize), Error> {
    let mut server_communication_cost: usize = 0;
    let mut total_server_time: f32 = 0.0;

    let listener: TcpListener = TcpListener::bind("127.0.0.1:8080").await?;

    if let Ok((mut socket, _)) = listener.accept().await {
        let mut server_steps: ServerSteps = ServerSteps::ServerResp;

        while server_steps != ServerSteps::Done {
            match server_steps {
                ServerSteps::ServerResp => {
                    // Buffer to store the incoming data
                    let mut server_buffer_size: [u8; 2] = [0u8; 2];

                    // Read the data received in the buffer
                    socket.read_exact(&mut server_buffer_size).await.unwrap();

                    let client_message_size: usize =
                        u16::from_le_bytes(server_buffer_size) as usize;
                    let mut buffer: Vec<u8> = vec![0u8; client_message_size];
                    socket.read_exact(&mut buffer).await.unwrap();

                    // Deserialize the data into the ciphertext and nonce
                    let (c_1, nonce_c_1): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();

                    // Start the timer now
                    let server_timer: Instant = Instant::now();

                    // Perform the Server_Resp operation
                    let (c_2, nonce_c_2, _) = tk_server.clone().server_resp(&c_1, &nonce_c_1);

                    total_server_time += server_timer.elapsed().as_secs_f32();

                    // Serialize the data so that it can be sent over the network
                    let serialized_data_to_be_sent: Vec<u8> =
                        to_vec(&(c_2.clone(), nonce_c_2.clone())).unwrap();

                    let mut server_message: Vec<u8> = Vec::new();
                    server_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
                    server_message.extend(serialized_data_to_be_sent);

                    socket.write_all(&server_message).await.unwrap();
                    server_communication_cost += c_2.len() + nonce_c_2.len();

                    server_steps = ServerSteps::Done;
                }
                _ => break,
            }
        }
    }

    Ok((total_server_time, server_communication_cost))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum ServerStepsWithAuth {
    ServerResp,
    ServerVerify,
    Done,
}

pub async fn tk_pake_allow_client_login_with_auth(
    tk_server: TkServer,
) -> Result<(f32, usize), Error> {
    let mut server_communication_cost: usize = 0;
    let mut total_server_time: f32 = 0.0;
    let mut shared_session_key: [u8; 32] = [0_u8; 32];

    let listener: TcpListener = TcpListener::bind("127.0.0.1:8080").await?;

    if let Ok((mut socket, _)) = listener.accept().await {
        let mut server_steps: ServerStepsWithAuth = ServerStepsWithAuth::ServerResp;

        while server_steps != ServerStepsWithAuth::Done {
            match server_steps {
                ServerStepsWithAuth::ServerResp => {
                    // Buffer to store the incoming data
                    let mut server_buffer_size: [u8; 2] = [0u8; 2];

                    // Read the data received in the buffer
                    socket.read_exact(&mut server_buffer_size).await.unwrap();

                    let client_message_size: usize =
                        u16::from_le_bytes(server_buffer_size) as usize;
                    let mut buffer: Vec<u8> = vec![0u8; client_message_size];
                    socket.read_exact(&mut buffer).await.unwrap();

                    // Deserialize the data into the ciphertext and nonce
                    let (c_1, nonce_c_1): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();

                    // Start the timer now
                    let server_timer: Instant = Instant::now();

                    // Perform the Server_Resp operation
                    let (c_2, nonce_c_2, session_key) =
                        tk_server.clone().server_resp(&c_1, &nonce_c_1);

                    total_server_time += server_timer.elapsed().as_secs_f32();

                    shared_session_key = session_key;

                    // Serialize the data so that it can be sent over the network
                    let serialized_data_to_be_sent: Vec<u8> =
                        to_vec(&(c_2.clone(), nonce_c_2.clone())).unwrap();

                    let mut server_message: Vec<u8> = Vec::new();
                    server_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
                    server_message.extend(serialized_data_to_be_sent);

                    socket.write_all(&server_message).await.unwrap();
                    server_communication_cost += c_2.len() + nonce_c_2.len();

                    server_steps = ServerStepsWithAuth::ServerVerify;
                }
                ServerStepsWithAuth::ServerVerify => {
                    // Buffer to store the incoming data
                    let mut server_buffer_size: [u8; 2] = [0u8; 2];

                    // Read the data received in the buffer
                    socket.read_exact(&mut server_buffer_size).await.unwrap();

                    let client_message_size: usize =
                        u16::from_le_bytes(server_buffer_size) as usize;
                    let mut buffer: Vec<u8> = vec![0u8; client_message_size];
                    socket.read_exact(&mut buffer).await.unwrap();

                    // Deserialize the data into client_sk_digest
                    let client_sk_digest: Vec<u8> = from_slice(&buffer).unwrap();

                    // Start the timer now
                    let server_timer: Instant = Instant::now();

                    let mut hash_func = Sha256::new();
                    hash_func.update(shared_session_key);

                    let sk_digest: [u8; 32] = hash_func.finalize().into();

                    let _ = sk_digest.to_vec() == client_sk_digest;

                    total_server_time += server_timer.elapsed().as_secs_f32();

                    server_steps = ServerStepsWithAuth::Done;
                }
                _ => break,
            }
        }
    }

    Ok((total_server_time, server_communication_cost))
}
