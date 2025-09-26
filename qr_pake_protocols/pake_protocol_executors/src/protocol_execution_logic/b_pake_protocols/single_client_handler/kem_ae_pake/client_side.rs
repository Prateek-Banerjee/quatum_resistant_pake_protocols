/*
[1] Efficient Asymmetric PAKE Compiler from KEM and AE
https://eprint.iacr.org/2024/1400
*/

use qr_pake_protocols::{AvailableVariants, KemAeClient};
use serde_json::{from_slice, to_vec};
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
    ClientFinish,
    Done,
}

pub async fn kem_ae_pake_register_client(
    client_id: &[u8],
    client_password: &[u8],
    protocol_variant: AvailableVariants,
) -> io::Result<KemAeClient> {
    let mut stream: TcpStream = TcpStream::connect("127.0.0.1:8080").await?;

    let mut kemae_client: KemAeClient = KemAeClient::new(
        client_id.to_vec(),
        client_password.to_vec(),
        protocol_variant,
    );

    let (rw, initial_kem_public_key) = kemae_client.generate_registration_details();

    // Perform the One-Time Client Registration by sending the
    // client ID, rw and the initial KEM public key to the server
    // Serialize the data so that it can be sent over the network
    let serialized_data_to_be_sent: Vec<u8> =
        to_vec(&(client_id.to_vec(), rw, initial_kem_public_key)).unwrap();

    let mut client_message: Vec<u8> = Vec::new();
    client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
    client_message.extend(serialized_data_to_be_sent);

    // Send the message to the server
    stream.write_all(&client_message).await.unwrap();

    Ok(kemae_client)
}

pub async fn kem_ae_pake_client_login(
    mut kemae_client: KemAeClient,
) -> Result<(f32, usize), Error> {
    let mut total_client_time: f32 = 0.0;
    let mut client_communication_cost: usize = 0;

    let mut stream: TcpStream = TcpStream::connect("127.0.0.1:8080").await?;

    let mut client_steps: ClientSteps = ClientSteps::ClientInit;

    while client_steps != ClientSteps::Done {
        match client_steps {
            ClientSteps::ClientInit => {
                // Start the timer
                let client_timer: Instant = Instant::now();

                // Perform the client_init operation
                let (c_1, nonce_c_1) = kemae_client.client_init();

                total_client_time += client_timer.elapsed().as_secs_f32();

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> =
                    to_vec(&(c_1.clone(), nonce_c_1.clone())).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u16).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                client_communication_cost += c_1.len() + nonce_c_1.len();

                client_steps = ClientSteps::ClientFinish;
            }
            ClientSteps::ClientFinish => {
                // Buffer to store the incoming data
                let mut client_buffer_size: [u8; 4] = [0u8; 4];

                stream.read_exact(&mut client_buffer_size).await.unwrap();

                let server_message_size: usize = u32::from_le_bytes(client_buffer_size) as usize;
                let mut buffer: Vec<u8> = vec![0u8; server_message_size];
                stream.read_exact(&mut buffer).await.unwrap();

                // Deserialize the data into a tuple (server_ciphertext, ciphertext_ae)
                let (c_2, nonce_c_2, psi, nonce_psi): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
                    from_slice(&buffer).unwrap();

                // Start the timer
                let client_timer: Instant = Instant::now();

                // Perform the Client Finish operation
                let (sigma, _) = kemae_client
                    .client_finish(c_2, &nonce_c_2, psi, &nonce_psi)
                    .unwrap();

                total_client_time += client_timer.elapsed().as_secs_f32();

                // Serialize the data so that it can be sent over the network
                let serialized_data_to_be_sent: Vec<u8> = to_vec(&(sigma)).unwrap();

                let mut client_message: Vec<u8> = Vec::new();
                client_message.extend((serialized_data_to_be_sent.len() as u8).to_le_bytes());
                client_message.extend(serialized_data_to_be_sent);

                // Send the message to the server
                stream.write_all(&client_message).await.unwrap();
                client_communication_cost += sigma.len();

                client_steps = ClientSteps::Done;
            }

            _ => break,
        }
    }
    thread::sleep(Duration::from_secs_f32(0.2));

    Ok((total_client_time, client_communication_cost))
}
