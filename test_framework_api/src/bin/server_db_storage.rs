#![allow(unused_imports)]
use qr_pake_protocol_executors::{
    DEFAULT_IP, DEFAULT_LOGIN_THRESHOLD, DEFAULT_LOGIN_WINDOW, DEFAULT_PORT, DEFAULT_TIMEOUT,
    DefaultStorage, Storage, start_server,
};
use qr_pake_protocols::{KemAeServer, OcakeServer, TkServer};
use std::sync::Arc;
use test_framework_api::other_storage::DbStorage;

#[tokio::main]
async fn main() {
    let path_to_db: String = "../protocol_state.db".to_string();

    // Create the SQLite database storage backend
    let storage = Arc::new(DbStorage::new(path_to_db)) as Arc<dyn Storage<_> + Send + Sync>;

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
