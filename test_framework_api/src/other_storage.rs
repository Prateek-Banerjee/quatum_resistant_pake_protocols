use qr_pake_protocol_executors::Storage;
use qr_pake_protocols::{AvailableVariants, KemAeServer, KemChoice, OcakeServer, TkServer};
use rusqlite::{Connection, OptionalExtension, Result, params};
use serde_json::{from_slice, to_vec};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DbStorage {
    db_connector: String,
}

impl DbStorage {
    pub fn new(db_connector: String) -> Self {
        Self { db_connector }
    }
}

impl<T: HelperFunctions + Default> Storage<T> for DbStorage {
    fn insert_server_instance(
        &self,
        client_id: Vec<u8>,
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        server_instance: &T,
    ) -> anyhow::Result<()> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let table_name: &'static str = server_instance.table_name();
        let server_state_serialized: Vec<u8> = server_instance.to_bytes();
        let protocol_variant_serialized: Vec<u8> = protocol_variant.to_bytes();

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();
                let query = format!(
                    "INSERT OR REPLACE INTO {} (client_id, protocol_variant, kem_choice, server_state, last_incorrect_login, is_client_blocked) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    table_name
                );
                // New entry: empty failed logins, not blocked
                let empty_vec: VecDeque<u64> = VecDeque::new();
                let last_incorrect_login: Vec<u8> = serde_json::to_vec(&empty_vec)?;
                let is_client_blocked: i32 = 0i32;

                connection.execute(
                    &query,
                    params![
                        client_id,
                        protocol_variant_serialized,
                        kem_choice_serialized,
                        server_state_serialized,
                        last_incorrect_login,
                        is_client_blocked
                    ],
                )?;
                Ok(())
            }
            None => {
                let query = format!(
                    "INSERT OR REPLACE INTO {} (client_id, protocol_variant, server_state, last_incorrect_login, is_client_blocked) VALUES (?1, ?2, ?3, ?4, ?5)",
                    table_name
                );
                // New entry: empty failed logins, not blocked
                let empty_vec: VecDeque<u64> = VecDeque::new();
                let last_incorrect_login: Vec<u8> = serde_json::to_vec(&empty_vec)?;
                let is_client_blocked: i32 = 0i32;

                connection.execute(
                    &query,
                    params![
                        client_id,
                        protocol_variant_serialized,
                        server_state_serialized,
                        last_incorrect_login,
                        is_client_blocked
                    ],
                )?;
                Ok(())
            }
        }
    }

    fn get_stored_server_instance(
        &self,
        client_id: Vec<u8>,
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<Option<T>> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let table_name: &'static str = T::table_name(&Default::default());
        let protocol_variant_serialized: Vec<u8> = protocol_variant.to_bytes();

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();

                let query: String = format!(
                    "SELECT server_state FROM {} WHERE client_id = ?1 and protocol_variant = ?2 and kem_choice = ?3",
                    table_name
                );

                let mut stmt = connection.prepare(&query)?;
                let mut rows = stmt.query(params![
                    client_id,
                    protocol_variant_serialized,
                    kem_choice_serialized
                ])?;

                if let Some(row) = rows.next()? {
                    let bytes: Vec<u8> = row.get(0)?;
                    let server_state: T = T::from_bytes(&bytes);
                    Ok(Some(server_state))
                } else {
                    Ok(None)
                }
            }
            None => {
                let query: String = format!(
                    "SELECT server_state FROM {} WHERE client_id = ?1 and protocol_variant = ?2 and kem_choice IS NULL",
                    table_name
                );

                let mut stmt = connection.prepare(&query)?;
                let mut rows = stmt.query(params![client_id, protocol_variant_serialized,])?;

                if let Some(row) = rows.next()? {
                    let bytes: Vec<u8> = row.get(0)?;
                    let server_state: T = T::from_bytes(&bytes);
                    Ok(Some(server_state))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn client_exists(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<bool> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let protocol_variant_serialized: Vec<u8> = protocol_variant.to_bytes();
        let table_name: &'static str = T::table_name(&Default::default());

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();
                let query: String = format!(
                    "SELECT EXISTS(SELECT 1 FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice = ?3)",
                    table_name
                );

                let mut stmt = connection.prepare(&query)?;
                let exists: i32 = stmt.query_row(
                    params![
                        client_id,
                        protocol_variant_serialized,
                        kem_choice_serialized
                    ],
                    |row| row.get(0),
                )?;
                Ok(exists != 0)
            }
            None => {
                let query: String = format!(
                    "SELECT EXISTS(SELECT 1 FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice IS NULL)",
                    table_name
                );

                let mut stmt = connection.prepare(&query)?;
                let exists: i32 = stmt
                    .query_row(params![client_id, protocol_variant_serialized], |row| {
                        row.get(0)
                    })?;
                Ok(exists != 0)
            }
        }
    }

    fn get_incorrect_login_attempts_count(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<usize> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let protocol_variant_serialized = protocol_variant.to_bytes();
        let table_name: &'static str = T::table_name(&Default::default());

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();

                let query = format!(
                    "SELECT last_incorrect_login FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice = ?3",
                    table_name
                );
                let mut stmt = connection.prepare(&query)?;
                let result: Option<Vec<u8>> = stmt
                    .query_row(
                        params![
                            client_id,
                            protocol_variant_serialized,
                            kem_choice_serialized
                        ],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(blob) = result {
                    let deque: VecDeque<u64> = serde_json::from_slice(&blob)?;
                    Ok(deque.len())
                } else {
                    Ok(0)
                }
            }
            None => {
                let query = format!(
                    "SELECT last_incorrect_login FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice IS NULL",
                    table_name
                );
                let mut stmt = connection.prepare(&query)?;
                let result: Option<Vec<u8>> = stmt
                    .query_row(params![client_id, protocol_variant_serialized,], |row| {
                        row.get(0)
                    })
                    .optional()?;
                if let Some(blob) = result {
                    let deque: VecDeque<u64> = serde_json::from_slice(&blob)?;
                    Ok(deque.len())
                } else {
                    Ok(0)
                }
            }
        }
    }

    fn record_incorrect_login_attempt(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        login_window: u64,
    ) -> anyhow::Result<usize> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let protocol_variant_serialized: Vec<u8> = protocol_variant.to_bytes();
        let table_name: &'static str = T::table_name(&Default::default());

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();

                // Get current deque
                let query: String = format!(
                    "SELECT last_incorrect_login FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice = ?3",
                    table_name
                );
                let mut stmt = connection.prepare(&query)?;
                let result: Option<Vec<u8>> = stmt
                    .query_row(
                        params![
                            client_id,
                            protocol_variant_serialized,
                            kem_choice_serialized
                        ],
                        |row| row.get(0),
                    )
                    .optional()?;
                let mut deque: VecDeque<u64> = if let Some(blob) = result {
                    serde_json::from_slice(&blob)?
                } else {
                    VecDeque::new()
                };

                // Remove old timestamps
                let now: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                while let Some(&front) = deque.front() {
                    if now.saturating_sub(front) > login_window {
                        deque.pop_front();
                    } else {
                        break;
                    }
                }
                deque.push_back(now);

                // Update DB
                let update_query = format!(
                    "UPDATE {} SET last_incorrect_login = ?4 WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice = ?3",
                    table_name
                );
                let serialized_deque: Vec<u8> = serde_json::to_vec(&deque)?;
                connection.execute(
                    &update_query,
                    params![
                        client_id,
                        protocol_variant_serialized,
                        kem_choice_serialized,
                        serialized_deque
                    ],
                )?;
                Ok(deque.len())
            }
            None => {
                // Get current deque
                let query: String = format!(
                    "SELECT last_incorrect_login FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice IS NULL",
                    table_name
                );
                let mut stmt = connection.prepare(&query)?;
                let result: Option<Vec<u8>> = stmt
                    .query_row(params![client_id, protocol_variant_serialized,], |row| {
                        row.get(0)
                    })
                    .optional()?;
                let mut deque: VecDeque<u64> = if let Some(blob) = result {
                    serde_json::from_slice(&blob)?
                } else {
                    VecDeque::new()
                };

                // Remove old timestamps
                let now: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                while let Some(&front) = deque.front() {
                    if now.saturating_sub(front) > login_window {
                        deque.pop_front();
                    } else {
                        break;
                    }
                }
                deque.push_back(now);

                // Update DB
                let update_query = format!(
                    "UPDATE {} SET last_incorrect_login = ?4 WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice IS NULL",
                    table_name
                );
                let serialized_deque: Vec<u8> = serde_json::to_vec(&deque)?;
                connection.execute(
                    &update_query,
                    params![client_id, protocol_variant_serialized, serialized_deque],
                )?;
                Ok(deque.len())
            }
        }
    }

    fn reset_incorrect_login_attempts(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<()> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let protocol_variant_serialized: Vec<u8> = protocol_variant.to_bytes();
        let table_name: &'static str = T::table_name(&Default::default());
        let empty_vec: VecDeque<u64> = VecDeque::new();
        let serialized_deque: Vec<u8> = serde_json::to_vec(&empty_vec)?;

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();

                let update_query: String = format!(
                    "UPDATE {} SET last_incorrect_login = ?4 WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice = ?3",
                    table_name
                );
                connection.execute(
                    &update_query,
                    params![
                        client_id,
                        protocol_variant_serialized,
                        kem_choice_serialized,
                        serialized_deque
                    ],
                )?;
                Ok(())
            }
            None => {
                let update_query: String = format!(
                    "UPDATE {} SET last_incorrect_login = ?4 WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice IS NULL",
                    table_name
                );
                connection.execute(
                    &update_query,
                    params![client_id, protocol_variant_serialized, serialized_deque],
                )?;
                Ok(())
            }
        }
    }

    fn block_client(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<()> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let protocol_variant_serialized: Vec<u8> = protocol_variant.to_bytes();
        let table_name: &'static str = T::table_name(&Default::default());

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();

                let update_query: String = format!(
                    "UPDATE {} SET is_client_blocked = 1 WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice = ?3",
                    table_name
                );
                connection.execute(
                    &update_query,
                    params![
                        client_id,
                        protocol_variant_serialized,
                        kem_choice_serialized
                    ],
                )?;
                Ok(())
            }
            None => {
                let update_query: String = format!(
                    "UPDATE {} SET is_client_blocked = 1 WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice IS NULL",
                    table_name
                );
                connection.execute(
                    &update_query,
                    params![client_id, protocol_variant_serialized,],
                )?;
                Ok(())
            }
        }
    }

    fn is_client_blocked(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<bool> {
        let connection: Connection = get_connection(&self.db_connector)?;
        let protocol_variant_serialized: Vec<u8> = protocol_variant.to_bytes();
        let table_name: &'static str = T::table_name(&Default::default());

        match kem_choice {
            Some(chosen_kem) => {
                let kem_choice_serialized: Vec<u8> = chosen_kem.to_bytes();

                let query: String = format!(
                    "SELECT is_client_blocked FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice = ?3",
                    table_name
                );
                let mut stmt = connection.prepare(&query)?;
                let result: Option<i32> = stmt
                    .query_row(
                        params![
                            client_id,
                            protocol_variant_serialized,
                            kem_choice_serialized
                        ],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(result.unwrap_or(0) != 0)
            }
            None => {
                let query: String = format!(
                    "SELECT is_client_blocked FROM {} WHERE client_id = ?1 AND protocol_variant = ?2 and kem_choice IS NULL",
                    table_name
                );
                let mut stmt = connection.prepare(&query)?;
                let result: Option<i32> = stmt
                    .query_row(params![client_id, protocol_variant_serialized,], |row| {
                        row.get(0)
                    })
                    .optional()?;
                Ok(result.unwrap_or(0) != 0)
            }
        }
    }
}

fn get_connection(path_to_db: &str) -> Result<Connection> {
    let connection: Connection = Connection::open(path_to_db)?;
    Ok(connection)
}

pub trait HelperFunctions: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
    fn table_name(&self) -> &'static str;
    fn delete_all_server_state(&self, path_to_db: &'static str) {
        let connection: Connection = get_connection(path_to_db).unwrap();
        let table_name: &'static str = self.table_name();

        let query: String = format!("DELETE FROM {}", table_name);
        connection
            .execute(&query, [])
            .expect(&format!("Failed to delete from table {}", table_name));
    }
}

impl HelperFunctions for KemAeServer {
    fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        from_slice(bytes).unwrap()
    }

    fn table_name(&self) -> &'static str {
        "kem_ae_pake"
    }
}

impl HelperFunctions for OcakeServer {
    fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        from_slice(bytes).unwrap()
    }

    fn table_name(&self) -> &'static str {
        "ocake_pake"
    }
}

impl HelperFunctions for TkServer {
    fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        from_slice(bytes).unwrap()
    }

    fn table_name(&self) -> &'static str {
        "tk_pake"
    }
}
