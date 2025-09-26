#![allow(unused_imports)]
use qr_pake_protocol_executors::{
    DEFAULT_IP, DEFAULT_LOGIN_THRESHOLD, DEFAULT_LOGIN_WINDOW, DEFAULT_PORT, DEFAULT_TIMEOUT,
    DefaultStorage, Storage, start_server,
};
use qr_pake_protocols::{KemAeServer, OcakeServer, TkServer};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Create the in-memory storage backend
    let storage =
        Arc::new(DefaultStorage::<KemAeServer>::new()) as Arc<dyn Storage<_> + Send + Sync>;

    start_server::<KemAeServer>(
        storage,
        DEFAULT_IP,
        DEFAULT_PORT,
        DEFAULT_LOGIN_THRESHOLD,
        DEFAULT_LOGIN_WINDOW,
        DEFAULT_TIMEOUT,
    )
    .await
    .expect("Server failed to start");
}
