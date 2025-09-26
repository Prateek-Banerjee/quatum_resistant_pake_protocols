/*
[1] Efficient Asymmetric PAKE Compiler from KEM and AE
https://eprint.iacr.org/2024/1400
*/

use qr_pake_protocols::{AvailableVariants, KemAeServer};
use serde_json::{from_slice, to_vec};
use std::{io::Error, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Clone, Copy, PartialEq, Debug)]
enum ServerSteps {
    ServerResponse,
    ServerFinish,
    Done,
}

pub async fn kem_ae_pake_accept_client_registration(
    protocol_variant: AvailableVariants,
) -> Result<KemAeServer, Error> {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:8080").await?;

    let mut kemae_server: KemAeServer = KemAeServer::new(protocol_variant);

    if let Ok((mut socket, _)) = listener.accept().await {
        // Buffer to store the incoming data
        let mut server_buffer_size: [u8; 2] = [0u8; 2];

        // Read the data received in the buffer
        socket.read_exact(&mut server_buffer_size).await.unwrap();

        let client_message_size = u16::from_le_bytes(server_buffer_size) as usize;
        let mut buffer: Vec<u8> = vec![0u8; client_message_size];
        socket.read_exact(&mut buffer).await.unwrap();

        // Deserialize the data into a tuple (client_id, rw, initial_kem_public_key)
        let (client_id, rw, initial_kem_public_key): (Vec<u8>, Vec<u8>, Vec<u8>) =
            from_slice(&buffer).unwrap();

        // One-Time Client Registration
        kemae_server.accept_registration(client_id, rw, initial_kem_public_key);
    }

    Ok(kemae_server)
}

pub async fn kem_ae_pake_allow_client_login(
    mut kemae_server: KemAeServer,
) -> Result<(f32, usize), Error> {
    let mut total_server_time: f32 = 0.0;
    let mut server_communication_cost: usize = 0;

    let listener: TcpListener = TcpListener::bind("127.0.0.1:8080").await?;

    if let Ok((mut socket, _)) = listener.accept().await {
        let mut server_steps: ServerSteps = ServerSteps::ServerResponse;

        while server_steps != ServerSteps::Done {
            match server_steps {
                ServerSteps::ServerResponse => {
                    // Buffer to store the incoming data
                    let mut server_buffer_size: [u8; 2] = [0u8; 2];

                    // Read the data received in the buffer
                    socket.read_exact(&mut server_buffer_size).await.unwrap();

                    let client_message_size = u16::from_le_bytes(server_buffer_size) as usize;
                    let mut buffer = vec![0u8; client_message_size];
                    socket.read_exact(&mut buffer).await.unwrap();

                    // Deserialize the data into the ciphertext and nonce
                    let (c_1, nonce_c_1): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();

                    // Start the timer
                    let server_timer: Instant = Instant::now();

                    // Perform the Server Response operation
                    let (c_2, nonce_c_2, psi, nonce_psi) =
                        kemae_server.server_resp(c_1, &nonce_c_1);

                    total_server_time += server_timer.elapsed().as_secs_f32();

                    // Serialize the data so that it can be sent over the network
                    let serialized_data_to_be_sent: Vec<u8> = to_vec(&(
                        c_2.clone(),
                        nonce_c_2.clone(),
                        psi.clone(),
                        nonce_psi.clone(),
                    ))
                    .unwrap();

                    let mut server_message: Vec<u8> = Vec::new();
                    server_message.extend((serialized_data_to_be_sent.len() as u32).to_le_bytes());
                    server_message.extend(serialized_data_to_be_sent);

                    socket.write_all(&server_message).await.unwrap();
                    server_communication_cost +=
                        c_2.len() + nonce_c_2.len() + psi.len() + nonce_psi.len();
                    server_steps = ServerSteps::ServerFinish;
                }
                ServerSteps::ServerFinish => {
                    // Buffer to store the incoming data
                    let mut server_buffer_size: [u8; 1] = [0u8; 1];

                    // Read the data received in the buffer
                    socket.read_exact(&mut server_buffer_size).await.unwrap();

                    let client_message_size: usize = u8::from_le_bytes(server_buffer_size) as usize;
                    let mut buffer: Vec<u8> = vec![0u8; client_message_size];
                    socket.read_exact(&mut buffer).await.unwrap();

                    // Deserialize the data into sigma
                    let sigma: Vec<u8> = from_slice(&buffer).unwrap();

                    // Start the timer
                    let server_timer: Instant = Instant::now();

                    // Perform the Server_Finish operation
                    let _ = kemae_server.server_finish(sigma);

                    total_server_time += server_timer.elapsed().as_secs_f32();

                    server_steps = ServerSteps::Done;
                }

                _ => break,
            }
        }
    }

    Ok((total_server_time, server_communication_cost))
}
