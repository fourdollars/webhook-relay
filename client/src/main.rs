use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, pkcs1v15::Pkcs1v15Encrypt};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{fs, path::PathBuf, sync::Arc, time::Instant};
use tokio::sync::Mutex;

use env_logger;
use futures::TryStreamExt;
use log;
use std::{env, process, time::Duration};

use eventsource_client as es;

// Heartbeat configuration constants
const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 30;
const MAX_RECONNECT_ATTEMPTS: u32 = 5;
const INITIAL_BACKOFF_SECS: u64 = 1;
const MAX_BACKOFF_SECS: u64 = 30;

#[derive(Debug, Clone)]
struct HeartbeatConfig {
    timeout: Duration,
    max_attempts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_HEARTBEAT_TIMEOUT_SECS),
            max_attempts: MAX_RECONNECT_ATTEMPTS,
            initial_backoff: Duration::from_secs(INITIAL_BACKOFF_SECS),
            max_backoff: Duration::from_secs(MAX_BACKOFF_SECS),
        }
    }
}

#[derive(Debug)]
struct ConnectionState {
    last_ping: Option<Instant>,
    is_connected: bool,
}

#[derive(Debug)]
enum AppError {
    Crypto(aes_gcm::Error),
    Io(std::io::Error),
    Rsa(rsa::Error),
    Pkcs8(pkcs8::Error),
    Base64(base64::DecodeError),
    ConnectionFailed(String),
    HeartbeatTimeout,
    Other(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Crypto(err) => write!(f, "Cryptographic error: {}", err),
            AppError::Io(err) => write!(f, "IO error: {}", err),
            AppError::Rsa(err) => write!(f, "RSA error: {}", err),
            AppError::Pkcs8(err) => write!(f, "PKCS8 error: {}", err),
            AppError::Base64(err) => write!(f, "Base64 decode error: {}", err),
            AppError::ConnectionFailed(err) => write!(f, "Connection failed: {}", err),
            AppError::HeartbeatTimeout => write!(f, "Heartbeat timeout detected"),
            AppError::Other(err) => write!(f, "Other error: {}", err),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Crypto(_) => None,
            AppError::Io(err) => Some(err),
            AppError::Rsa(err) => Some(err),
            AppError::Pkcs8(err) => Some(err),
            AppError::Base64(err) => Some(err),
            AppError::ConnectionFailed(_) => None,
            AppError::HeartbeatTimeout => None,
            AppError::Other(_) => None,
        }
    }
}

impl From<aes_gcm::Error> for AppError {
    fn from(err: aes_gcm::Error) -> Self {
        AppError::Crypto(err)
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err)
    }
}

impl From<rsa::Error> for AppError {
    fn from(err: rsa::Error) -> Self {
        AppError::Rsa(err)
    }
}

impl From<pkcs8::Error> for AppError {
    fn from(err: pkcs8::Error) -> Self {
        AppError::Pkcs8(err)
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(err: base64::DecodeError) -> Self {
        AppError::Base64(err)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Payload {
    body: String,
    headers: String,
}

fn decrypt_asymmetric(
    to_decrypt_base64: &str,
    private_key_path: &PathBuf,
) -> Result<Vec<u8>, AppError> {
    let private_key_pem = fs::read_to_string(private_key_path)?;
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&private_key_pem).map_err(|e| AppError::Pkcs8(e.into()))?;

    let encrypted_bytes = general_purpose::STANDARD.decode(to_decrypt_base64)?;

    let padding = Pkcs1v15Encrypt;
    let decrypted = private_key.decrypt(padding, &encrypted_bytes)?;
    Ok(decrypted)
}

fn decrypt_symmetric(
    encrypted_string: &str,
    private_key_path: &PathBuf,
) -> Result<String, AppError> {
    let parts: Vec<&str> = encrypted_string.split(':').collect();
    if parts.len() != 3 {
        return Err(AppError::Other(
            "Invalid encrypted string format".to_string(),
        ));
    }

    let encrypted_symmetric_key_base64 = parts[0];
    let nonce_base64 = parts[1];
    let ciphertext_base64 = parts[2];

    // 1. Decrypt the symmetric key using asymmetric decryption
    let decrypted_symmetric_key_bytes =
        decrypt_asymmetric(encrypted_symmetric_key_base64, private_key_path)?;
    let key = Key::<Aes256Gcm>::from_slice(&decrypted_symmetric_key_bytes);
    let cipher = Aes256Gcm::new(key);

    // 2. Decode Nonce and ciphertext
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_base64)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_base64)?;

    // 3. Decrypt the ciphertext
    let decrypted_text_bytes = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(String::from_utf8(decrypted_text_bytes)
        .map_err(|e| AppError::Other(format!("UTF-8 decode error: {}", e)))?)
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Webhook Relay Client");
        eprintln!();
        eprintln!("USAGE:");
        eprintln!("    {} <url> <private_key_path>", args[0]);
        eprintln!();
        eprintln!("ARGS:");
        eprintln!("    <url>              Server-sent events URL to connect to");
        eprintln!("    <private_key_path> Path to RSA private key file for decryption");
        eprintln!();
        eprintln!("BEHAVIOR:");
        eprintln!("    The client connects to the SSE endpoint and monitors for webhook events.");
        eprintln!("    It automatically detects server disconnections via heartbeat monitoring");
        eprintln!("    and attempts to reconnect with exponential backoff.");
        eprintln!();
        eprintln!("HEARTBEAT & RECONNECTION:");
        eprintln!(
            "    - Heartbeat timeout: {} seconds",
            DEFAULT_HEARTBEAT_TIMEOUT_SECS
        );
        eprintln!(
            "    - Max reconnection attempts: {}",
            MAX_RECONNECT_ATTEMPTS
        );
        eprintln!(
            "    - Backoff strategy: exponential ({}s, 2s, 4s, 8s, 16s, max {}s)",
            INITIAL_BACKOFF_SECS, MAX_BACKOFF_SECS
        );
        eprintln!();
        eprintln!("EXIT CODES:");
        eprintln!("    0 - Success (normal shutdown)");
        eprintln!("    1 - Connection failure (server unreachable after max attempts)");
        eprintln!("    2 - Configuration error (invalid arguments or key file)");
        process::exit(2);
    }

    let url = &args[1];
    let private_key_path = PathBuf::from(&args[2]);
    let config = HeartbeatConfig::default();

    let connection_state = Arc::new(Mutex::new(ConnectionState {
        last_ping: None,
        is_connected: false,
    }));

    match run_client_with_reconnection(url, &private_key_path, config, connection_state).await {
        Ok(_) => {
            log::info!("Client exited successfully");
            Ok(())
        }
        Err(AppError::ConnectionFailed(msg)) => {
            log::error!("Connection failed: {}", msg);
            process::exit(1);
        }
        Err(AppError::HeartbeatTimeout) => {
            log::error!("Heartbeat timeout - server appears to be unresponsive");
            process::exit(1);
        }
        Err(err) => {
            log::error!("Application error: {}", err);
            process::exit(2);
        }
    }
}

async fn run_client_with_reconnection(
    url: &str,
    private_key_path: &PathBuf,
    config: HeartbeatConfig,
    connection_state: Arc<Mutex<ConnectionState>>,
) -> Result<(), AppError> {
    let mut current_attempt = 0;
    let mut backoff_duration = config.initial_backoff;

    loop {
        log::info!("Attempting to connect to {}", url);

        let client = es::ClientBuilder::for_url(url)
            .map_err(|e| AppError::ConnectionFailed(format!("Failed to create client: {}", e)))?
            .reconnect(
                es::ReconnectOptions::reconnect(false) // We handle reconnection ourselves
                    .build(),
            )
            .build();

        // Reset connection state for new attempt
        {
            let mut state = connection_state.lock().await;
            state.last_ping = None;
            state.is_connected = false;
        }

        let result =
            run_client_session(client, private_key_path, &config, connection_state.clone()).await;

        match result {
            Ok(_) => {
                log::info!("Client session ended successfully");
                return Ok(());
            }
            Err(AppError::HeartbeatTimeout) | Err(AppError::ConnectionFailed(_)) => {
                current_attempt += 1;

                // Log appropriately based on error type
                match &result {
                    Err(AppError::HeartbeatTimeout) => {
                        log::info!(
                            "Heartbeat timeout detected, attempting reconnection ({}/{})",
                            current_attempt,
                            config.max_attempts
                        );
                    }
                    Err(AppError::ConnectionFailed(msg))
                        if msg.contains("Eof") || msg.contains("Connection refused") =>
                    {
                        log::info!(
                            "Connection lost, attempting reconnection ({}/{})",
                            current_attempt,
                            config.max_attempts
                        );
                    }
                    _ => {
                        log::warn!(
                            "Connection failed (attempt {}/{}): {:?}",
                            current_attempt,
                            config.max_attempts,
                            result
                        );
                    }
                }

                if current_attempt >= config.max_attempts {
                    return Err(AppError::ConnectionFailed(format!(
                        "Max reconnection attempts ({}) exceeded",
                        config.max_attempts
                    )));
                }

                log::info!("Reconnecting in {:?}...", backoff_duration);
                tokio::time::sleep(backoff_duration).await;

                // Exponential backoff with max limit
                backoff_duration = std::cmp::min(backoff_duration * 2, config.max_backoff);
            }
            Err(err) => {
                return Err(err);
            }
        }
    }
}

async fn run_client_session(
    client: impl es::Client,
    private_key_path: &PathBuf,
    config: &HeartbeatConfig,
    connection_state: Arc<Mutex<ConnectionState>>,
) -> Result<(), AppError> {
    let private_key_path = private_key_path.clone();

    // Start heartbeat monitoring task
    let heartbeat_state = connection_state.clone();
    let heartbeat_timeout = config.timeout;
    let mut heartbeat_task: tokio::task::JoinHandle<Result<(), AppError>> =
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5)); // Check every 5 seconds

            loop {
                interval.tick().await;

                let state = heartbeat_state.lock().await;
                if let Some(last_ping) = state.last_ping {
                    if state.is_connected && last_ping.elapsed() > heartbeat_timeout {
                        log::error!(
                            "Heartbeat timeout: no ping received for {:?} (threshold: {:?})",
                            last_ping.elapsed(),
                            heartbeat_timeout
                        );
                        return Err(AppError::HeartbeatTimeout);
                    }
                }
            }
        });

    // Process the event stream
    let stream_result = async {
        let mut stream = client.stream();

        loop {
            match stream.try_next().await {
                Ok(Some(event)) => {
                    match event {
                        es::SSE::Connected(connection) => {
                            log::info!(
                                "Connected to server, status={}",
                                connection.response().status()
                            );
                            let mut state = connection_state.lock().await;
                            state.is_connected = true;
                            state.last_ping = Some(Instant::now()); // Initialize ping time on connection
                        }
                        es::SSE::Event(ev) => match ev.event_type.as_str() {
                            "ping" => {
                                let mut state = connection_state.lock().await;
                                state.last_ping = Some(Instant::now());
                                log::debug!("Received ping event, updated heartbeat timestamp");
                            }
                            "webhook" => {
                                let data = match general_purpose::STANDARD.decode(&ev.data) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        eprintln!("Failed to decode webhook data: {}", e);
                                        continue;
                                    }
                                };
                                if let Ok(payload) = serde_json::from_slice::<Payload>(&data) {
                                    match serde_json::to_string(&payload) {
                                        Ok(payload) => {
                                            println!("{}", payload);
                                        }
                                        Err(e) => eprintln!("Webhook event unknown data: {}", e),
                                    }
                                } else {
                                    eprintln!("Webhook event unknown data: {:?}", data);
                                }
                            }
                            "encrypted" => match decrypt_symmetric(&ev.data, &private_key_path) {
                                Ok(decrypted) => {
                                    if let Ok(payload) =
                                        serde_json::from_slice::<Payload>(decrypted.as_bytes())
                                    {
                                        match serde_json::to_string(&payload) {
                                            Ok(payload) => {
                                                println!("{}", payload);
                                            }
                                            Err(e) => {
                                                eprintln!("Encrypted event unknown data: {}", e)
                                            }
                                        }
                                    } else {
                                        eprintln!("Encrypted event unknown data: {:?}", decrypted);
                                    }
                                }
                                Err(e) => eprintln!("Failed to decrypt event: {}", e),
                            },
                            _ => log::warn!("Received unknown event type: {}", ev.event_type),
                        },
                        es::SSE::Comment(comment) => {
                            log::debug!("Received comment: {}", comment);
                        }
                    }
                }
                Ok(None) => {
                    // Stream ended
                    log::info!("Event stream ended");
                    break;
                }
                Err(e) => {
                    // Check if this is an expected disconnection (Eof or connection refused)
                    let error_str = format!("{:?}", e);
                    if error_str.contains("Eof") {
                        log::info!("Server closed connection");
                    } else {
                        log::error!("Stream error: {:?}", e);
                    }
                    return Err(AppError::ConnectionFailed(format!("Stream error: {:?}", e)));
                }
            }
        }

        Ok::<(), AppError>(())
    };

    // Wait for either stream to end or heartbeat timeout
    tokio::select! {
        result = stream_result => {
            // Stream ended, abort heartbeat monitoring
            heartbeat_task.abort();
            result
        }
        heartbeat_result = &mut heartbeat_task => {
            // Heartbeat timeout occurred - this is the expected path when server stops pinging
            // We don't need to read the stream result as we're intentionally disconnecting
            match heartbeat_result {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(err)) => {
                    log::info!("Disconnecting due to heartbeat timeout");
                    Err(err)
                },
                Err(_) => Ok(()), // Task was aborted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_config_defaults() {
        let config = HeartbeatConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_backoff, Duration::from_secs(1));
        assert_eq!(config.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_connection_state_initialization() {
        let state = ConnectionState {
            last_ping: None,
            is_connected: false,
        };

        assert!(state.last_ping.is_none());
        assert!(!state.is_connected);
    }

    #[tokio::test]
    async fn test_heartbeat_timeout_calculation() {
        let config = HeartbeatConfig::default();
        let connection_state = Arc::new(Mutex::new(ConnectionState {
            last_ping: Some(Instant::now() - Duration::from_secs(35)), // 35 seconds ago
            is_connected: true,
        }));

        let state = connection_state.lock().await;
        if let Some(last_ping) = state.last_ping {
            assert!(last_ping.elapsed() > config.timeout);
        }
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let config = HeartbeatConfig::default();
        let mut backoff = config.initial_backoff;

        // Test exponential backoff progression
        assert_eq!(backoff, Duration::from_secs(1));

        backoff = std::cmp::min(backoff * 2, config.max_backoff);
        assert_eq!(backoff, Duration::from_secs(2));

        backoff = std::cmp::min(backoff * 2, config.max_backoff);
        assert_eq!(backoff, Duration::from_secs(4));

        backoff = std::cmp::min(backoff * 2, config.max_backoff);
        assert_eq!(backoff, Duration::from_secs(8));

        backoff = std::cmp::min(backoff * 2, config.max_backoff);
        assert_eq!(backoff, Duration::from_secs(16));

        backoff = std::cmp::min(backoff * 2, config.max_backoff);
        assert_eq!(backoff, Duration::from_secs(30)); // Capped at max_backoff

        backoff = std::cmp::min(backoff * 2, config.max_backoff);
        assert_eq!(backoff, Duration::from_secs(30)); // Still capped
    }
}
