/*
[1] Efficient Asymmetric PAKE Compiler from KEM and AE
https://eprint.iacr.org/2024/1400
*/

use crate::protocol_execution_logic::b_pake_protocols::single_client_handler::kem_ae_pake::{
    client_side::*, server_side::*,
};
use qr_pake_protocols::{AvailableVariants, KemAeClient, KemAeServer};
use std::{thread, time::Duration};
use tokio::{io, spawn};

pub async fn perform_kem_ae_pake_client_registration(
    client_id: &[u8],
    client_password: &[u8],
    chosen_protocol_variant: AvailableVariants,
) -> io::Result<(KemAeClient, KemAeServer)> {
    // Spawn the server as an asynchronous task
    let server_handler =
        spawn(async move { kem_ae_pake_accept_client_registration(chosen_protocol_variant).await });

    // Sleeping to let the server start properly
    thread::sleep(Duration::from_millis(10));

    // Invoke the client
    let kem_ae_client: KemAeClient =
        kem_ae_pake_register_client(&client_id, client_password, chosen_protocol_variant).await?;

    let kem_ae_server: KemAeServer = server_handler.await??;

    Ok((kem_ae_client, kem_ae_server))
}

pub async fn execute_kem_ae_pake(
    registered_clients: Vec<(KemAeClient, KemAeServer)>,
) -> io::Result<(Vec<f32>, usize, Vec<f32>, usize)> {
    let mut client_execution_times: Vec<f32> = vec![];
    let mut server_execution_times: Vec<f32> = vec![];
    let mut communication_cost_client: usize = 0;
    let mut communication_cost_server: usize = 0;

    for (kemae_client, kemae_server) in registered_clients {
        // Spawn the server as an asynchronous task
        let server_handler =
            spawn(async move { kem_ae_pake_allow_client_login(kemae_server).await });

        // Sleeping to let the server start properly
        thread::sleep(Duration::from_millis(10));

        // Invoke the client
        let (client_time, comm_cost_client) = kem_ae_pake_client_login(kemae_client).await?;
        client_execution_times.push(client_time);
        communication_cost_client = comm_cost_client;

        // Receive the server communication cost from the spawned task
        let (server_time, comm_cost_server) = server_handler.await??;
        server_execution_times.push(server_time);
        communication_cost_server = comm_cost_server;
    }

    Ok((
        client_execution_times,
        communication_cost_client,
        server_execution_times,
        communication_cost_server,
    ))
}
