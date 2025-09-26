mod executors;
mod protocol_execution_logic;

pub use crate::{
    executors::b_pake_protocols::{
        bench_api,
        generic_client::{login, register},
        generic_server::start_server,
    },
    protocol_execution_logic::b_pake_protocols::multi_client_handler::{
        client_handler::ClientHandler,
        server_handler::ServerHandler,
        storage_handler::{DefaultStorage, Storage},
    },
};

pub const DEFAULT_IP: &str = "127.0.0.1";
pub const DEFAULT_PORT: &str = "8080";
pub const DEFAULT_LOGIN_THRESHOLD: usize = 3;
pub const DEFAULT_LOGIN_WINDOW: u64 = 60;
pub const DEFAULT_TIMEOUT: u64 = 5;
