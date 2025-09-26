use qr_pake_protocols::{AvailableVariants, KemChoice};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, SystemTime},
};

/// Default implementation of the storage backend for server state management.
///
/// # Fields:
/// - `hash_map`: `Mutex<HashMap<(Vec<u8>, AvailableVariants, Option<KemChoice>), ServerState<T>>>` - Internal map storing server state for each client, keyed by client ID, protocol variant, and optional KEM choice.
pub struct DefaultStorage<T> {
    hash_map: Mutex<HashMap<(Vec<u8>, AvailableVariants, Option<KemChoice>), ServerState<T>>>,
}

/// Represents the state of a server for a specific client.
///
/// # Fields:
/// - `server_instance`: `T` - The server instance associated with the client.
/// - `last_incorrect_login_attempts`: `VecDeque<SystemTime>` - Queue of timestamps for recent incorrect login attempts.
/// - `is_client_blocked`: `bool` - Indicates whether the client is already blocked or not.
struct ServerState<T> {
    server_instance: T,
    last_incorrect_login_attempts: VecDeque<SystemTime>,
    is_client_blocked: bool,
}

/// Trait for managing server state which is stored in a shared storage. This trait defines
/// methods for inserting, retrieving, and managing server instances along with handling
/// (multiple) incorrect client login attempts.
///
/// # Required Methods:
/// - `insert_server_instance`: Stores a server instance for a client.
/// - `get_stored_server_instance`: Retrieves a stored server instance for a client.
/// - `client_exists`: Checks if a client exists in storage.
/// - `get_incorrect_login_attempts_count`: Gets the count of recent incorrect login attempts for a client.
/// - `record_incorrect_login_attempt`: Records an incorrect login attempt for a client.
/// - `reset_incorrect_login_attempts`: Resets the incorrect login attempts for a client.
/// - `block_client`: Blocks a client from further login attempts.
/// - `is_client_blocked`: Checks if a client is currently blocked.
pub trait Storage<T> {
    fn insert_server_instance(
        &self,
        client_id: Vec<u8>,
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        server_instance: &T,
    ) -> anyhow::Result<()>;

    fn get_stored_server_instance(
        &self,
        client_id: Vec<u8>,
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<Option<T>>;

    fn client_exists(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<bool>;

    fn get_incorrect_login_attempts_count(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<usize>;

    fn record_incorrect_login_attempt(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        login_window: u64,
    ) -> anyhow::Result<usize>;

    fn reset_incorrect_login_attempts(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<()>;

    fn block_client(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<()>;

    fn is_client_blocked(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<bool>;
}

impl<T> DefaultStorage<T> {
    pub fn new() -> Self {
        DefaultStorage {
            hash_map: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: Clone + Send + 'static> Storage<T> for DefaultStorage<T> {
    /// Stores a server instance for a client in the storage backend.
    ///
    /// # Parameters:
    /// - `client_id`: `Vec<u8>` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    /// - `server_instance`: `&T` - The server instance to store.
    ///
    /// # Returns:
    /// - `anyhow::Result<()>` - Returns `Ok(())`
    fn insert_server_instance(
        &self,
        client_id: Vec<u8>,
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        server_instance: &T,
    ) -> anyhow::Result<()> {
        let mut map = self.hash_map.lock().unwrap();
        map.insert(
            (client_id, protocol_variant, kem_choice),
            ServerState {
                server_instance: server_instance.clone(),
                last_incorrect_login_attempts: VecDeque::new(),
                is_client_blocked: false,
            },
        );
        Ok(())
    }

    /// Retrieves a stored server instance for a client from the storage backend.
    ///
    /// # Parameters:
    /// - `client_id`: `Vec<u8>` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    ///
    /// # Returns:
    /// - `anyhow::Result<Option<T>>` - Returns `Ok(Some(server_instance))` if found, `Ok(None)` if not found, or an error otherwise.
    fn get_stored_server_instance(
        &self,
        client_id: Vec<u8>,
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<Option<T>> {
        let map = self.hash_map.lock().unwrap();
        Ok(map
            .get(&(client_id, protocol_variant, kem_choice))
            .map(|entry| entry.server_instance.clone()))
    }

    /// Checks if a client exists in the storage backend, to ensure if the client is registered or not.
    ///
    /// # Parameters:
    /// - `client_id`: `&[u8]` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    ///
    /// # Returns:
    /// - `anyhow::Result<bool>` - Returns `Ok(true)` if the client exists, `Ok(false)` if not, or an error otherwise.
    fn client_exists(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<bool> {
        let map = self.hash_map.lock().unwrap();
        Ok(map.contains_key(&(client_id.to_vec(), protocol_variant, kem_choice)))
    }

    /// Gets the count of recent incorrect login attempts for a client.
    ///
    /// # Parameters:
    /// - `client_id`: `&[u8]` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    ///
    /// # Returns:
    /// - `anyhow::Result<usize>` - Returns `Ok(count)` with the number of incorrect login attempts, or `Ok(0)` if the client is not found, or an error otherwise.
    fn get_incorrect_login_attempts_count(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<usize> {
        let map = self.hash_map.lock().unwrap();
        Ok(map
            .get(&(client_id.to_vec(), protocol_variant, kem_choice))
            .map(|entry| entry.last_incorrect_login_attempts.len())
            .unwrap_or(0))
    }

    /// Records an incorrect login attempt for a client and updates the attempt history within the specified time window.
    ///
    /// # Parameters:
    /// - `client_id`: `&[u8]` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    /// - `login_window`: `u64` - The time window (in seconds) for tracking login attempts.
    ///
    /// # Returns:
    /// - `anyhow::Result<usize>` - Returns `Ok(count)` with the number of incorrect login attempts within the window, or an error if the client is not found.
    fn record_incorrect_login_attempt(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
        login_window: u64,
    ) -> anyhow::Result<usize> {
        let mut map = self.hash_map.lock().unwrap();
        if let Some(entry) = map.get_mut(&(client_id.to_vec(), protocol_variant, kem_choice)) {
            let now: SystemTime = SystemTime::now();

            // Remove timestamps older than LOGIN_WINDOW_SECS
            while let Some(&front) = entry.last_incorrect_login_attempts.front() {
                if now
                    .duration_since(front)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs()
                    > login_window
                {
                    entry.last_incorrect_login_attempts.pop_front();
                } else {
                    break;
                }
            }
            entry.last_incorrect_login_attempts.push_back(now);

            // Increment the incorrect login counter
            // entry.incorrect_login_counter += 1;
            Ok(entry.last_incorrect_login_attempts.len())
        } else {
            Err(anyhow::anyhow!("Client not found"))
        }
    }

    /// Resets the incorrect login attempts for a client in the storage backend.
    ///
    /// # Parameters:
    /// - `client_id`: `&[u8]` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    ///
    /// # Returns:
    /// - `anyhow::Result<()>` - Returns `Ok(())` if the operation is successful, or an error if the client is not found.
    fn reset_incorrect_login_attempts(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<()> {
        let mut map = self.hash_map.lock().unwrap();
        if let Some(entry) = map.get_mut(&(client_id.to_vec(), protocol_variant, kem_choice)) {
            entry.last_incorrect_login_attempts.clear();
            // entry.incorrect_login_counter = 0;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Client not found"))
        }
    }

    /// Blocks a client from performing further logins.
    ///
    /// # Parameters:
    /// - `client_id`: `&[u8]` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    ///
    /// # Returns:
    /// - `anyhow::Result<()>` - Returns `Ok(())` if the operation is successful, or an error if the client is not found.
    fn block_client(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<()> {
        let mut map = self.hash_map.lock().unwrap();
        if let Some(entry) = map.get_mut(&(client_id.to_vec(), protocol_variant, kem_choice)) {
            entry.is_client_blocked = true;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Client not found"))
        }
    }

    /// Checks if a client is already blocked or not from performing further logins.
    ///
    /// # Parameters:
    /// - `client_id`: `&[u8]` - The identifier of the client.
    /// - `protocol_variant`: `AvailableVariants` - The protocol variant in use.
    /// - `kem_choice`: `Option<KemChoice>` - Optional KEM choice for the protocol.
    ///
    /// # Returns:
    /// - `anyhow::Result<bool>` - Returns `Ok(true)` if the client is blocked, `Ok(false)` if not, or an error otherwise.
    fn is_client_blocked(
        &self,
        client_id: &[u8],
        protocol_variant: AvailableVariants,
        kem_choice: Option<KemChoice>,
    ) -> anyhow::Result<bool> {
        let map = self.hash_map.lock().unwrap();
        Ok(map
            .get(&(client_id.to_vec(), protocol_variant, kem_choice))
            .map(|entry| entry.is_client_blocked)
            .unwrap_or(false))
    }
}
