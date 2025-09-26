# Overview of the Project

This project comprises of the implementation of three recent propositions of quantum-resistant PAKE Protocols. They are referred in the implementation and the [report](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/blob/master/Master%20Thesis%20Report.pdf) with the following names as per the following resources:

1) [TK-PAKE](https://iacr.steepath.eu/2023/1334-AGenericConstructionofTightlySecurePasswordbasedAuthenticatedKeyExchange.pdf)
2) [*Modified* OCAKE-PAKE](https://eprint.iacr.org/2023/1368.pdf)
3) [KEM-AE-PAKE](https://eprint.iacr.org/2024/1400.pdf)

## Navigating the Codebase
1) [qr_pake_protocols/src/](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/tree/master/qr_pake_protocols/src): The core implementation of the above three PAKE protocols. 

2) [qr_pake_protocols/pake_protocol_executors/](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/tree/master/qr_pake_protocols/pake_protocol_executors): Another workspace member-crate that uses Tokio and provides a client-server application which executes the three PAKE protocols underneath.

## Examples and Usage 

For all the examples, please refer to [test_framework_api/src/](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/tree/master/test_framework_api/src). See [test_framework_api/src/Cargo.toml](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/blob/master/test_framework_api/Cargo.toml) as it uses the [qr_pake_protocols](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/tree/master/qr_pake_protocols) as a dependency. A sample execution of the [TK-PAKE](https://iacr.steepath.eu/2023/1334-AGenericConstructionofTightlySecurePasswordbasedAuthenticatedKeyExchange.pdf) is demonstrated below.

**Server Binary**

```bash
use qr_pake_protocol_executors::{start_server, DefaultStorage, Storage, DEFAULT_IP, DEFAULT_LOGIN_THRESHOLD,
    DEFAULT_LOGIN_WINDOW, DEFAULT_PORT, DEFAULT_TIMEOUT};
use qr_pake_protocols::TkServer;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Create the in-memory storage backend
    let storage = Arc::new(DefaultStorage::<TkServer>::new()) as Arc<dyn Storage<_> + Send + Sync>;

    start_server::<TkServer>(storage, DEFAULT_IP, DEFAULT_PORT, DEFAULT_LOGIN_THRESHOLD, DEFAULT_LOGIN_WINDOW, DEFAULT_TIMEOUT)
        .await .expect("Server failed to start");
}
```

**Client Binary**

```bash
use qr_pake_protocol_executors::{login, register, DEFAULT_IP, DEFAULT_PORT};
use qr_pake_protocols::{AvailableVariants::Recommended, TkClient};

#[tokio::main]
async fn main() {
    let client_id = b"This is a default pake client id";
    let client_password = b"This is client default password.";

    // Perform registration
    let client_instance = register::<TkClient>(client_id, client_password, Recommended, None, DEFAULT_IP, DEFAULT_PORT)
        .await.expect("Registration failed");

    // Perform login
    let session_key: [u8; 32] = login::<TkClient>(client_instance, DEFAULT_IP, DEFAULT_PORT)
        .await.expect("Login failed");
    println!("\x1b[92m\t Client's Session Key: {:?} \x1b[0m\n", session_key);
}
```

**Execution:** Execute the server binary at first, so that the server starts and then execute the client binary.

### Important Note

The server-side of the PAKE protocols in this project is backed by HashMap-based *DefaultStorage* which implements a *Storage* trait. But, a user can implement the *Storage* trait for their own storage backend. The [test_framework_api/src/other_storage.rs](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/blob/master/test_framework_api/src/other_storage.rs) uses a SQLite database storage which implements the *Storage* trait.

#### Database Setup

Download the [DB Browser for SQLite](https://sqlitebrowser.org/dl/). We have used the *64-bit* Windows installer. We encourage a user to execute the [`create_tables.sql`](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/blob/master/create_tables.sql) at first. Then, the [`server_db_storage.rs`](https://github.com/Prateek-Banerjee/quatum_resistant_pake_protocols/blob/master/test_framework_api/src/bin/server_db_storage.rs) can also be used with the SQLite database as the storage solution.