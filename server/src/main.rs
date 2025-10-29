use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder, body::BodyStream, get,
    middleware::NormalizePath, post, web,
};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use futures_util::stream::StreamExt;
use hmac::{Hmac, Mac};
use pkcs8::DecodePublicKey;
use rand_core::{OsRng, RngCore};
use rsa::{RsaPublicKey, pkcs1v15::Pkcs1v15Encrypt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast::{self, Sender};
use tokio_stream::wrappers::BroadcastStream;

#[macro_use]
extern crate log;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Payload {
    body: String,
    headers: String,
}

type GlobalChannels = Arc<Mutex<HashMap<String, Sender<Payload>>>>;

fn encrypt_asymmetric(to_encrypt: &[u8], public_key_path: &PathBuf) -> Result<String, Error> {
    let public_key_pem = fs::read_to_string(public_key_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem).map_err(|e| {
        error!("Failed to parse public key: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to parse public key")
    })?;

    let padding = Pkcs1v15Encrypt;
    match public_key.encrypt(&mut OsRng, padding, to_encrypt) {
        Ok(encrypted) => Ok(general_purpose::STANDARD.encode(encrypted)),
        Err(e) => {
            error!("Failed to encrypt payload: {}", e);
            Err(actix_web::error::ErrorInternalServerError(
                "Failed to encrypt payload",
            ))
        }
    }
}

fn encrypt_symmetric(text: &str, public_key_path: &PathBuf) -> Result<String, Error> {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = <Aes256Gcm as aes_gcm::aead::KeyInit>::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = match cipher.encrypt(nonce, text.as_bytes()) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            error!("Failed to encrypt payload: {}", e);
            return Err(actix_web::error::ErrorInternalServerError(
                "Failed to encrypt payload",
            ));
        }
    };

    let encrypted_symmetric_key = encrypt_asymmetric(&key_bytes, public_key_path)?;

    Ok(format!(
        "{}:{}:{}",
        encrypted_symmetric_key,
        general_purpose::STANDARD.encode(&nonce_bytes),
        general_purpose::STANDARD.encode(&ciphertext)
    ))
}

fn format_encrypted_event(data: &str, id: &str) -> String {
    let public_key_path = PathBuf::from(format!("pem/{}", id));
    match encrypt_symmetric(data, &public_key_path) {
        Ok(encrypted_string) => {
            format!(
                "event: encrypted\ndata: {}\nid: {}\n\n",
                encrypted_string,
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            )
        }
        Err(e) => {
            error!("Failed to encrypt payload: {}", e);
            String::new()
        }
    }
}

fn format_webhook_event(data: &str) -> String {
    let data = general_purpose::STANDARD.encode(data);
    format!(
        "event: webhook\ndata: {}\nid: {}\n\n",
        data,
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    )
}

fn format_ping_event(data: &str) -> String {
    format!(
        "event: ping\ndata: {}\nid: {}\n\n",
        data,
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    )
}

fn format_error_event(data: &str) -> String {
    format!(
        "event: error\ndata: {}\nid: {}\n\n",
        data,
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    )
}

// --- Channel Management Functions ---

/// Gets or creates a new SSE stream channel (broadcast mode).
/// This function is called when a client connects to `/{id}`.
/// It returns a Stream that needs to be wrapped by `BodyStream` to be used as an `HttpResponse` body.
fn get_or_create_stream_channel_stream(
    id: String,
    channels: GlobalChannels,
) -> impl futures_util::stream::Stream<Item = Result<web::Bytes, Error>> + 'static {
    let mut map = channels.lock().unwrap(); // Simplified error handling, production should be more robust

    let sender = map.entry(id.clone()).or_insert_with(|| {
        // If no channel exists for this ID, create a new broadcast channel.
        // Buffer size of 1024 means up to 1024 payloads can be stored if not received.
        // If the buffer is full, sending will return an Err(SendError::Full).
        let (tx, _rx) = broadcast::channel::<Payload>(1024);
        info!("New broadcast channel '{}' created.", id);
        tx
    });

    // Subscribe a new receiver from the existing or newly created sender.
    // Each new client will get its own receiver here, ensuring all receive payloads.
    let rx = sender.subscribe();
    info!("Client subscribed to channel '{}'.", id);

    // Convert the BroadcastStream into a `Stream<Item = Result<Bytes, Error>>`,
    // which is the expected Item type for `actix_web::body::BodyStream`.
    BroadcastStream::new(rx).map(move |result| {
        let formatted_bytes = match result {
            Ok(payload) => {
                let json_string = serde_json::to_string(&payload).unwrap_or_else(|e| {
                    debug!("Failed to serialize Payload: {}", e);
                    // Return an error JSON if serialization fails
                    format!(r#"{{"error": "Failed to serialize payload: {}"}}"#, e)
                });
                if payload.headers.len() > 0 {
                    println!("{} {}", Utc::now(), &id);
                    if let Ok(headers_value) =
                        serde_json::from_str::<Value>(payload.headers.as_str())
                    {
                        if let Ok(headers) = serde_json::to_string_pretty(&headers_value) {
                            println!("{}", headers);
                        } else {
                            println!("Failed to serialize headers: {}", payload.headers);
                        }
                    } else {
                        println!("Failed to deserialize headers: {}", payload.headers);
                    }
                    if let Ok(body_value) = serde_json::from_str::<Value>(payload.body.as_str()) {
                        if let Ok(body) = serde_json::to_string_pretty(&body_value) {
                            println!("{}", body);
                        } else {
                            println!("Failed to serialize body: {}", payload.body);
                        }
                    } else {
                        println!("Failed to deserialize body: {}", payload.body);
                    }
                    let encrypted = format_encrypted_event(&json_string, &id);
                    if encrypted.len() > 0 {
                        encrypted
                    } else {
                        format_webhook_event(&json_string)
                    }
                } else {
                    format_ping_event(payload.body.as_str())
                }
            }
            Err(e) => {
                // Handle receive errors (e.g., Lagged error if receiver falls too far behind)
                error!("Error receiving payload for channel '{}': {}", id, e);
                format_error_event(&format!("Error receiving payload: {}", e))
            }
        };
        // Convert the String to web::Bytes as required by BodyStream
        Ok(web::Bytes::from(formatted_bytes))
    })
}

/// Gets the existing SSE stream channel's sender.
/// This is called when a POST request is received to send a payload to a channel.
fn get_broadcast_sender(id: String, channels: GlobalChannels) -> Result<Sender<Payload>, Error> {
    let map = channels.lock().map_err(|e| {
        error!("Failed to lock channels: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to access channels")
    })?;

    map.get(&id)
        .cloned() // Get an owned copy of the Sender
        .ok_or_else(|| {
            error!("Broadcast channel '{}' not found for sending.", id);
            actix_web::error::ErrorNotFound(format!("Broadcast channel '{}' not found", id))
        })
}

fn list_channels_page(public_path: &str, channels: GlobalChannels) -> String {
    let mut content = String::new();
    let map = channels.lock().unwrap();
    for (id, sender) in map.iter() {
        let num_clients = match sender.receiver_count() {
            1 => "1 client".to_string(),
            n => format!("{} clients", n),
        };
        content.push_str(&format!(
            "<li><a href=\"{}/{}\">{}</a> ({})</li>",
            public_path, id, id, num_clients
        ));
    }
    content
}

struct AppState {
    channels: GlobalChannels,
    pass: String,
    public_path: String,
    user: String,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("<h1>Webhook Relay</h1>")
}

#[get("/admin")]
async fn admin(req: HttpRequest, data: web::Data<AppState>) -> HttpResponse {
    let auth = req.headers().get("Authorization");

    if auth.is_none() {
        let mut response = HttpResponse::Unauthorized().finish();
        response.headers_mut().insert(
            actix_web::http::header::WWW_AUTHENTICATE,
            actix_web::http::header::HeaderValue::from_static("Basic realm=\"401\""),
        );
        return response;
    }

    if let Some(auth) = auth {
        let auth = auth.to_str().unwrap_or("");
        if auth
            == format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", data.user, data.pass))
            )
        {
            let content = format!(
                "<html><body><h1>Channels</h1><ul>{}</ul></body></html>",
                list_channels_page(&data.public_path, data.channels.clone())
            );
            return HttpResponse::Ok().body(content);
        }
    }
    HttpResponse::Unauthorized().body("Unauthorized")
}

#[get("/favicon.ico")]
async fn favicon() -> impl Responder {
    HttpResponse::Ok().body("")
}

#[get("/{id}")]
async fn relay_get(id: web::Path<String>, data: web::Data<AppState>) -> HttpResponse {
    if id.len() != 40 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest().body("Invalid channel ID");
    }
    let mut res_builder = HttpResponse::Ok();
    res_builder
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"));

    res_builder.body(BodyStream::new(get_or_create_stream_channel_stream(
        id.into_inner(),
        data.channels.clone(),
    )))
}

enum SignatureType {
    XHubSignature,
    XGitlabToken,
    XLineSignature,
}

fn get_secret_key(id: &str) -> String {
    let secret_path = format!("secret/{}", id);
    std::fs::read_to_string(&secret_path).unwrap_or_else(|e| {
        error!("Failed to read secret key: {}", e);
        "".to_string()
    })
}

fn validate_signature(
    signature_type: SignatureType,
    expected_signature: &str,
    payload: &str,
    secret_key: &str,
) -> bool {
    if secret_key.is_empty() {
        error!(
            "Error: Secret key is empty for channel '{}'.",
            expected_signature
        );
        return false;
    }
    match signature_type {
        SignatureType::XHubSignature => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret_key.as_bytes())
                .expect("HMAC can take any key size in test");
            mac.update(payload.as_bytes());
            let signature_bytes = mac.finalize().into_bytes();
            let signature = format!("sha1={}", hex::encode(signature_bytes));
            if signature != expected_signature {
                return false;
            }
        }
        SignatureType::XGitlabToken => {
            if expected_signature != secret_key {
                return false;
            }
        }
        SignatureType::XLineSignature => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes())
                .expect("HMAC can take any key size in test");
            mac.update(payload.as_bytes());
            let signature_bytes = mac.finalize().into_bytes();
            let signature = format!(
                "sha256={}",
                general_purpose::STANDARD.encode(signature_bytes)
            );
            if signature != expected_signature {
                return false;
            }
        }
    };
    true
}

/// Handles POST requests to broadcast a payload to a specific SSE channel.
#[post("/{id}")]
async fn relay_post(
    req: HttpRequest,
    id: web::Path<String>,
    mut payload: web::Payload,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if id.len() != 40 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(HttpResponse::BadRequest().body("Invalid channel ID"));
    }
    let sender = get_broadcast_sender(id.clone(), data.channels.clone())?;
    let mut data = String::new();

    // Iterate over the payload chunks to read the incoming data.
    while let Some(chunk_result) = payload.next().await {
        let chunk = chunk_result?; // `chunk` is now of type `web::Bytes`
        data.push_str(&String::from_utf8_lossy(&chunk));
    }

    // Extract headers into a HashMap<String, String>
    let mut headers = HashMap::new();
    let mut valid = true;
    for (key, value) in req.headers().iter() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(key.to_string(), value_str.to_string());
            match key.as_str() {
                "x-hub-signature" => {
                    valid = validate_signature(
                        SignatureType::XHubSignature,
                        value_str,
                        &data,
                        &get_secret_key(&id),
                    )
                }
                "x-gitlab-token" => {
                    valid = validate_signature(
                        SignatureType::XGitlabToken,
                        value_str,
                        &data,
                        &get_secret_key(&id),
                    )
                }
                "x-line-signature" => {
                    valid = validate_signature(
                        SignatureType::XLineSignature,
                        value_str,
                        &data,
                        &get_secret_key(&id),
                    )
                }
                _ => (),
            }
        } else {
            warn!("Warning: Header value for '{}' is not valid UTF-8.", key);
        }
    }

    // Create the Payload instance
    let payload = Payload {
        body: data,
        headers: serde_json::to_string(&headers).unwrap(),
    };

    info!("Received: {:#?}", payload);

    if !valid {
        return Err(actix_web::error::ErrorUnauthorized("Invalid signature"));
    }

    // Send the payload to all subscribers of the broadcast channel.
    // `sender.send()` returns an `Err` if all receivers have been dropped or the channel is closed.
    if let Err(e) = sender.send(payload) {
        error!("Failed to send payload to broadcast channel: {}", e);
        // In a more robust application, you might want to remove the channel from the HashMap here
        return Err(actix_web::error::ErrorInternalServerError(
            "Failed to broadcast payload",
        ));
    }
    Ok(HttpResponse::Ok().finish())
}

async fn not_found(req: HttpRequest) -> impl Responder {
    let path = req.uri().path();
    error!("{:?} {} Not Found", req, path);
    HttpResponse::NotFound().body(format!("<h1>404 Not Found</h1>"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Environment variable configuration for host and port
    let host = std::env::var("HOST").unwrap_or("0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or("3000".to_string());
    let addr = format!("{}:{}", host, port);
    let user = std::env::var("AUTH_USER").unwrap_or("user".to_string());
    let pass = std::env::var("AUTH_PASS").unwrap_or("pass".to_string());
    let public_path = std::env::var("APP_PUBLIC_PATH").unwrap_or_else(|_| "".to_string());
    let base_path = std::env::var("APP_BASE_PATH").unwrap_or_else(|_| "".to_string());

    // Ping interval configuration for heartbeat testing (in milliseconds)
    let ping_interval_ms: u64 = std::env::var("PING_INTERVAL_MS")
        .unwrap_or("7500".to_string())
        .parse()
        .unwrap_or(7500);

    // Ping stop configuration for heartbeat testing (in seconds)
    let ping_stop_after_seconds: Option<u64> = std::env::var("PING_STOP_AFTER_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok());

    // Server shutdown configuration for testing (in seconds)
    let server_shutdown_after_seconds: Option<u64> = std::env::var("SERVER_SHUTDOWN_AFTER_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok());

    if let Some(stop_after) = ping_stop_after_seconds {
        if let Some(shutdown_after) = server_shutdown_after_seconds {
            info!(
                "Starting webhook relay service on http://{}{} with ping interval {}ms (will stop pings after {}s, shutdown after {}s)",
                addr, public_path, ping_interval_ms, stop_after, shutdown_after
            );
        } else {
            info!(
                "Starting webhook relay service on http://{}{} with ping interval {}ms (will stop pings after {}s)",
                addr, public_path, ping_interval_ms, stop_after
            );
        }
    } else if let Some(shutdown_after) = server_shutdown_after_seconds {
        info!(
            "Starting webhook relay service on http://{}{} with ping interval {}ms (will shutdown after {}s)",
            addr, public_path, ping_interval_ms, shutdown_after
        );
    } else {
        info!(
            "Starting webhook relay service on http://{}{} with ping interval {}ms",
            addr, public_path, ping_interval_ms
        );
    }

    // Initialize the global channels HashMap.
    // Arc enables shared ownership across threads, Mutex ensures exclusive access for modification.
    let channels: GlobalChannels = Arc::new(Mutex::new(HashMap::new()));

    let channels_for_tokio = channels.clone(); // Clone for the tokio::spawn block
    let ping_interval = ping_interval_ms; // Capture for the spawned task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(ping_interval));
        let start_time = std::time::Instant::now();

        loop {
            interval.tick().await;

            // Check if we should stop sending pings after specified time
            if let Some(stop_after_seconds) = ping_stop_after_seconds {
                if start_time.elapsed().as_secs() >= stop_after_seconds {
                    info!(
                        "Stopping ping events after {} seconds as configured",
                        stop_after_seconds
                    );
                    break;
                }
            }

            let channels_clone_inner = channels_for_tokio.clone(); // Clone for the inner tokio::spawn
            tokio::spawn(async move {
                let mut channels_guard = channels_clone_inner.lock().unwrap(); // Get a mutable lock

                // Collect IDs to remove first to avoid issues with mutable and immutable borrows
                let mut ids_to_remove = Vec::new();
                for (id, sender) in channels_guard.iter() {
                    if sender.receiver_count() == 0 {
                        ids_to_remove.push(id.clone()); // Store the ID to remove later
                    } else {
                        _ = sender.send(Payload {
                            body: format!("{}", sender.receiver_count()),
                            headers: "".to_string(),
                        });
                    }
                }

                // Now remove the collected IDs
                for id in ids_to_remove {
                    channels_guard.remove(&id);
                    info!("Removed channel {}", id);
                }
            })
            .await
            .unwrap();
        }
    });

    // Spawn a task to shutdown server after specified time (for testing)
    if let Some(shutdown_after_seconds) = server_shutdown_after_seconds {
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(shutdown_after_seconds)).await;
            info!(
                "Shutting down server after {} seconds as configured",
                shutdown_after_seconds
            );
            std::process::exit(0);
        });
    }

    let app_state = web::Data::new(AppState {
        channels: channels.clone(),
        pass: pass.clone(),
        public_path: public_path.clone(),
        user: user.clone(),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(index)
            .service(favicon)
            .service(admin)
            .wrap(NormalizePath::new(
                actix_web::middleware::TrailingSlash::Trim,
            ))
            .service(
                web::scope(&base_path)
                    .service(relay_get)
                    .service(relay_post),
            )
            .default_service(web::to(not_found))
    })
    .bind(addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;

    #[derive(Debug)]
    enum AppError {
        Crypto(aes_gcm::Error),
        Io(std::io::Error),
        Rsa(rsa::Error),
        Pkcs8(pkcs8::Error),
        Base64(base64::DecodeError),
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

    fn decrypt_asymmetric(
        to_decrypt_base64: &str,
        private_key_path: &PathBuf,
    ) -> Result<Vec<u8>, AppError> {
        let private_key_pem = fs::read_to_string(private_key_path)?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)
            .map_err(|e| AppError::Pkcs8(e.into()))?;

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
        let cipher = <Aes256Gcm as aes_gcm::aead::KeyInit>::new(key);

        // 2. Decode Nonce and ciphertext
        let nonce_bytes = general_purpose::STANDARD.decode(nonce_base64)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = general_purpose::STANDARD.decode(ciphertext_base64)?;

        // 3. Decrypt the ciphertext
        let decrypted_text_bytes = cipher.decrypt(nonce, ciphertext.as_ref())?;
        Ok(String::from_utf8(decrypted_text_bytes)
            .map_err(|e| AppError::Other(format!("UTF-8 decode error: {}", e)))?)
    }
    #[test]
    fn test_encrypted_decrypted() {
        let public_key_path = PathBuf::from("../tests/public_key.pem");
        let private_key_path = PathBuf::from("../tests/private_key.pem");
        let original_plaintext =
            "This is a secret message used for testing encryption and decryption!";
        let encrypted_string = encrypt_symmetric(original_plaintext, &public_key_path).unwrap();
        let decrypted_plaintext = decrypt_symmetric(&encrypted_string, &private_key_path).unwrap();
        assert_eq!(original_plaintext, decrypted_plaintext);
    }
    #[test]
    fn test_x_hub_signature() {
        let secret_key = "secret";
        let payload = "payload";

        let mut mac = Hmac::<Sha1>::new_from_slice(secret_key.as_bytes())
            .expect("HMAC can take any key size in test");
        mac.update(payload.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let calculated_signature = format!("sha1={}", hex::encode(signature_bytes));

        let expected_signature = &calculated_signature;

        let signature_type = SignatureType::XHubSignature;
        let valid = validate_signature(signature_type, expected_signature, payload, secret_key);
        assert!(
            valid,
            "X-Hub-Signature validation failed: calculated '{:?}', expected '{:?}'",
            calculated_signature, expected_signature
        );
    }
    #[test]
    fn test_x_gitlab_token() {
        let secret_key = "secret";
        let payload = "payload";

        let valid =
            validate_signature(SignatureType::XGitlabToken, secret_key, payload, secret_key);
        assert!(
            valid,
            "X-Gitlab-Token validation failed: calculated '{}', expected '{}'",
            secret_key, secret_key
        );
    }
    #[test]
    fn test_x_line_signature() {
        let secret_key = "secret";
        let payload = "payload";

        let mut mac = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes())
            .expect("HMAC can take any key size in test");
        mac.update(payload.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let calculated_signature = format!(
            "sha256={}",
            general_purpose::STANDARD.encode(signature_bytes)
        );

        let expected_signature = &calculated_signature;

        let signature_type = SignatureType::XLineSignature;
        let valid = validate_signature(signature_type, expected_signature, payload, secret_key);
        assert!(
            valid,
            "X-Line-Signature validation failed: calculated '{}', expected '{}'",
            calculated_signature, expected_signature
        );
    }
}
