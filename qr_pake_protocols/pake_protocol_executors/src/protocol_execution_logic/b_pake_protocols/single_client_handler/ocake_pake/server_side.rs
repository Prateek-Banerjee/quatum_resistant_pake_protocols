/*
[1] Towards post-quantum secure PAKE-A tight security proof for OCAKE in the BPR model
https://eprint.iacr.org/2023/1368.pdf
*/

use qr_pake_protocols::{AvailableVariants, KemChoice, OcakeServer};
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

pub async fn ocake_pake_accept_client_registration(
    protocol_variant: AvailableVariants,
    kem_choice: KemChoice,
) -> Result<OcakeServer, Error> {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:8080").await?;

    let mut ocake_server: OcakeServer = OcakeServer::new(protocol_variant);

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
        ocake_server.accept_registration(client_id, client_password, kem_choice);
    }

    Ok(ocake_server)
}

pub async fn ocake_pake_allow_client_login(
    mut ocake_server: OcakeServer,
) -> Result<(f32, usize), Error> {
    let mut server_communication_cost: usize = 0;
    let mut total_server_time: f32 = 0.0;

    let listener: TcpListener = TcpListener::bind("127.0.0.1:8080").await?;

    if let Ok((mut socket, _)) = listener.accept().await {
        let mut server_steps: ServerSteps = ServerSteps::ServerResponse;

        while server_steps != ServerSteps::Done {
            match server_steps {
                ServerSteps::ServerResponse => {
                    // Buffer to store the incoming data
                    let mut server_buffer_size: [u8; 4] = [0u8; 4];

                    // Read the data received in the buffer
                    socket.read_exact(&mut server_buffer_size).await.unwrap();

                    let client_message_size: usize =
                        u32::from_le_bytes(server_buffer_size) as usize;
                    let mut buffer: Vec<u8> = vec![0u8; client_message_size];
                    socket.read_exact(&mut buffer).await.unwrap();

                    // Deserialize the data into the ciphertext and nonce
                    let (c, nonce_c): (Vec<u8>, Vec<u8>) = from_slice(&buffer).unwrap();

                    // Start the timer
                    let server_timer: Instant = Instant::now();

                    // Perform the Server_Resp operation
                    let (kem_ciphertext, tag_one) = ocake_server.server_resp(&c, &nonce_c);

                    total_server_time += server_timer.elapsed().as_secs_f32();

                    // Serialize the data so that it can be sent over the network
                    let serialized_data_to_be_sent: Vec<u8> =
                        to_vec(&(kem_ciphertext.to_vec(), tag_one.to_vec())).unwrap();

                    let mut server_message: Vec<u8> = Vec::new();
                    server_message.extend((serialized_data_to_be_sent.len() as u32).to_le_bytes());
                    server_message.extend(serialized_data_to_be_sent);

                    socket.write_all(&server_message).await.unwrap();
                    server_communication_cost += kem_ciphertext.len() + tag_one.len();

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

                    // Deserialize the data into tag_two
                    let tag_two: Vec<u8> = from_slice(&buffer).unwrap();

                    // Start the timer
                    let server_timer: Instant = Instant::now();

                    // Perform the Server_Finish operation
                    let _ = ocake_server.server_finish(&tag_two);

                    total_server_time += server_timer.elapsed().as_secs_f32();

                    server_steps = ServerSteps::Done;
                }
                _ => break,
            }
        }
    }

    Ok((
        total_server_time,
        server_communication_cost,
    ))
}
