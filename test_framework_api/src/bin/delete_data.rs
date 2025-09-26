use qr_pake_protocols::{KemAeServer, OcakeServer, TkServer};
use test_framework_api::other_storage::HelperFunctions;

fn main() {
    let path_to_db = "../protocol_state.db";
    KemAeServer::default().delete_all_server_state(path_to_db);
    OcakeServer::default().delete_all_server_state(path_to_db);
    TkServer::default().delete_all_server_state(path_to_db);
}
