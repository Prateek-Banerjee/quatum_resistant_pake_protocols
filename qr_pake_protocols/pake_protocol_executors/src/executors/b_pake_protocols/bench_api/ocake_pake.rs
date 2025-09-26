/*
[1] Towards post-quantum secure PAKE-A tight security proof for OCAKE in the BPR model
https://eprint.iacr.org/2023/1368.pdf
*/

use crate::protocol_execution_logic::b_pake_protocols::single_client_handler::ocake_pake::{
    client_side::*, server_side::*,
};
use qr_pake_protocols::{AvailableVariants, KemChoice, OcakeClient, OcakeServer};
use std::{thread, time::Duration};
use tokio::{io, spawn};

pub async fn perform_ocake_pake_client_registration(
    client_id: &[u8],
    client_password: &[u8],
    chosen_protocol_variant: AvailableVariants,
    kem_choice: KemChoice,
) -> io::Result<(OcakeClient, OcakeServer)> {
    // Spawn the server as an asynchronous task
    let server_handler = spawn(async move {
        ocake_pake_accept_client_registration(chosen_protocol_variant, kem_choice).await
    });

    // Sleeping to let the server start properly
    thread::sleep(Duration::from_millis(10));

    // Invoke the client
    let ocake_client: OcakeClient = ocake_pake_register_client(
        &client_id,
        client_password,
        chosen_protocol_variant,
        kem_choice,
    )
    .await?;

    let ocake_server: OcakeServer = server_handler.await??;

    Ok((ocake_client, ocake_server))
}

pub async fn execute_ocake_pake(
    registered_clients: Vec<(OcakeClient, OcakeServer)>,
) -> io::Result<(Vec<f32>, usize, Vec<f32>, usize)> {
    let mut client_execution_times: Vec<f32> = vec![];
    let mut server_execution_times: Vec<f32> = vec![];
    let mut communication_cost_client: usize = 0;
    let mut communication_cost_server: usize = 0;

    for (ocake_client, ocake_server) in registered_clients {
        // Spawn the server as an asynchronous task
        let server_handler =
            spawn(async move { ocake_pake_allow_client_login(ocake_server).await });

        // Sleeping to let the server start properly
        thread::sleep(Duration::from_millis(10));

        // Invoke the client
        let (client_time, comm_cost_client) = ocake_pake_client_login(ocake_client).await?;
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
