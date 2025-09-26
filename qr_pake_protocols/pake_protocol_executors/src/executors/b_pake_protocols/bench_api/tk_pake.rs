/*
[1] A Generic Construction of Tightly Secure Password-based Authenticated Key Exchange
https://eprint.iacr.org/2023/1334
*/

use crate::protocol_execution_logic::b_pake_protocols::single_client_handler::tk_pake::{
    client_side::*, server_side::*,
};
use qr_pake_protocols::{AvailableVariants, TkClient, TkServer};
use std::{thread, time::Duration};
use tokio::{io, spawn};

pub async fn perform_tk_pake_client_registration(
    client_id: &[u8],
    client_password: &[u8],
    chosen_protocol_variant: AvailableVariants,
) -> io::Result<(TkClient, TkServer)> {
    // Spawn the server as an asynchronous task
    let server_handler =
        spawn(async move { tk_pake_accept_client_registration(chosen_protocol_variant).await });

    // Sleeping to let the server start properly
    thread::sleep(Duration::from_millis(10));

    // Invoke the client
    let tk_client: TkClient =
        tk_pake_register_client(&client_id, client_password, chosen_protocol_variant).await?;

    let tk_server: TkServer = server_handler.await??;

    Ok((tk_client, tk_server))
}

pub async fn execute_tk_pake(
    registered_clients: Vec<(TkClient, TkServer)>,
    authenticate: bool,
) -> io::Result<(Vec<f32>, usize, Vec<f32>, usize)> {
    let mut client_execution_times: Vec<f32> = vec![];
    let mut server_execution_times: Vec<f32> = vec![];
    let mut communication_cost_client: usize = 0;
    let mut communication_cost_server: usize = 0;

    for (tk_client, tk_server) in registered_clients {
        if authenticate {
            // Spawn the server as an asynchronous task
            let server_handler =
                spawn(async move { tk_pake_allow_client_login_with_auth(tk_server).await });

            // Sleeping to let the server start properly
            thread::sleep(Duration::from_millis(10));

            // Invoke the client
            let (client_time, comm_cost_client) = tk_pake_client_login_with_auth(tk_client).await?;
            client_execution_times.push(client_time);
            communication_cost_client = comm_cost_client;

            // Receive the server communication cost from the spawned task
            let (server_time, comm_cost_server) = server_handler.await??;
            server_execution_times.push(server_time);
            communication_cost_server = comm_cost_server;
        } else {
            // Spawn the server as an asynchronous task
            let server_handler = spawn(async move { tk_pake_allow_client_login(tk_server).await });

            // Sleeping to let the server start properly
            thread::sleep(Duration::from_millis(10));

            // Invoke the client
            let (client_time, comm_cost_client) = tk_pake_client_login(tk_client).await?;
            client_execution_times.push(client_time);
            communication_cost_client = comm_cost_client;

            // Receive the server communication cost from the spawned task
            let (server_time, comm_cost_server) = server_handler.await??;
            server_execution_times.push(server_time);
            communication_cost_server = comm_cost_server;
        }
    }

    Ok((
        client_execution_times,
        communication_cost_client,
        server_execution_times,
        communication_cost_server,
    ))
}
