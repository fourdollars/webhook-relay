use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder, body::BodyStream, get,
    middleware::NormalizePath, post, web,
};
use aes_gcm::{Aes256Gcm, aead::Aead};
use base64::{Engine as _, engine::general_purpose};
use futures_util::stream::StreamExt;
use hmac::{Hmac, Mac};
use pkcs8::DecodePublicKey;
use rand_core::{OsRng, RngCore};
use rsa::{RsaPublicKey, pkcs1v15::Pkcs1v15Encrypt};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
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

#[allow(deprecated)]
fn encrypt_symmetric(text: &str, public_key_path: &PathBuf) -> Result<String, Error> {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = <Aes256Gcm as aes_gcm::aead::KeyInit>::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

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
                    debug!("Delivering webhook to subscriber on channel '{}'", id);
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

fn unauthorized_basic_response(realm: &str) -> HttpResponse {
    let mut response = HttpResponse::Unauthorized().finish();
    response.headers_mut().insert(
        actix_web::http::header::WWW_AUTHENTICATE,
        actix_web::http::header::HeaderValue::from_str(&format!("Basic realm=\"{}\"", realm))
            .unwrap_or_else(|_| {
                actix_web::http::header::HeaderValue::from_static("Basic realm=\"401\"")
            }),
    );
    response
}

fn read_channel_auth_token(id: &str) -> Result<Option<String>, std::io::Error> {
    let auth_path = format!("auth/{}", id);
    match std::fs::read_to_string(&auth_path) {
        Ok(raw) => {
            let token = raw.trim().to_string();
            if token.is_empty() {
                warn!("auth file is empty for channel '{}': {}", id, auth_path);
                Ok(None)
            } else {
                Ok(Some(token))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn extract_basic_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}

struct AppState {
    channels: GlobalChannels,
    /// Expected `Authorization: Basic` token for `/admin`; `None` disables the endpoint.
    admin_token: Option<String>,
    /// `LOG_PAYLOADS=1`: allow logging webhook bodies at debug level.
    log_payloads: bool,
    /// `MAX_BODY_BYTES`: largest accepted webhook body; larger requests get 413.
    max_body_bytes: usize,
    public_path: String,
}

/// Builds the `/admin` Basic auth token. Returns `None` (endpoint disabled)
/// unless a non-empty password is configured, so there is no default credential.
fn admin_token(user: Option<String>, pass: Option<String>) -> Option<String> {
    let pass = pass.filter(|p| !p.is_empty())?;
    let user = user.filter(|u| !u.is_empty()).unwrap_or("user".to_string());
    Some(general_purpose::STANDARD.encode(format!("{}:{}", user, pass)))
}

fn is_admin_authorized(req: &HttpRequest, expected: &str) -> bool {
    extract_basic_token(req)
        .is_some_and(|got| bool::from(got.as_bytes().ct_eq(expected.as_bytes())))
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("<h1>Webhook Relay</h1>")
}

#[get("/admin")]
async fn admin(req: HttpRequest, data: web::Data<AppState>) -> HttpResponse {
    let Some(expected) = data.admin_token.as_deref() else {
        return HttpResponse::NotFound().body("<h1>404 Not Found</h1>");
    };

    if !is_admin_authorized(&req, expected) {
        return unauthorized_basic_response("401");
    }

    let content = format!(
        "<html><body><h1>Channels</h1><ul>{}</ul></body></html>",
        list_channels_page(&data.public_path, data.channels.clone())
    );
    HttpResponse::Ok().body(content)
}

#[get("/favicon.ico")]
async fn favicon() -> impl Responder {
    HttpResponse::Ok().body("")
}

#[get("/{id}")]
async fn relay_get(
    req: HttpRequest,
    id: web::Path<String>,
    data: web::Data<AppState>,
) -> HttpResponse {
    if id.len() != 40 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest().body("Invalid channel ID");
    }

    let channel_id = id.into_inner();
    match read_channel_auth_token(&channel_id) {
        Ok(Some(expected_token)) => {
            let got_token = extract_basic_token(&req);
            if got_token.as_deref() != Some(expected_token.as_str()) {
                warn!("Unauthorized SSE subscribe for channel '{}'", channel_id);
                return unauthorized_basic_response("sse");
            }
        }
        Ok(None) => {}
        Err(e) => {
            error!(
                "Failed to read auth token for channel '{}': {}",
                channel_id, e
            );
            return HttpResponse::InternalServerError().body("Failed to load channel auth");
        }
    }

    let mut res_builder = HttpResponse::Ok();
    res_builder
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        // Disable nginx proxy buffering so SSE events (pings and webhooks) are
        // forwarded to the client immediately instead of being held in the buffer.
        // Without this, pings accumulate in nginx's buffer after a webhook flush
        // and the client sees no pings for 30+ seconds, triggering heartbeat timeouts.
        .insert_header(("X-Accel-Buffering", "no"));

    res_builder.body(BodyStream::new(get_or_create_stream_channel_stream(
        channel_id,
        data.channels.clone(),
    )))
}

#[derive(Clone, Copy)]
enum SignatureType {
    XHubSignature,
    XHubSignature256,
    XGitlabToken,
    XLineSignature,
}

const SIGNATURE_HEADERS: [(&str, SignatureType); 4] = [
    ("x-hub-signature-256", SignatureType::XHubSignature256),
    ("x-hub-signature", SignatureType::XHubSignature),
    ("x-gitlab-token", SignatureType::XGitlabToken),
    ("x-line-signature", SignatureType::XLineSignature),
];

/// Returns `Ok(None)` when the channel has no secret file configured.
fn get_secret_key(id: &str) -> std::io::Result<Option<String>> {
    let secret_path = format!("secret/{}", id);
    match std::fs::read_to_string(&secret_path) {
        Ok(secret) => Ok(Some(secret)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn verify_hmac_hex<M: Mac + hmac::digest::KeyInit>(
    secret_key: &str,
    payload: &str,
    signature: &str,
    prefix: &str,
) -> bool {
    let Some(hex_sig) = signature.strip_prefix(prefix) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = <M as Mac>::new_from_slice(secret_key.as_bytes()) else {
        return false;
    };
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}

fn validate_signature(
    signature_type: SignatureType,
    expected_signature: &str,
    payload: &str,
    secret_key: &str,
) -> bool {
    if secret_key.is_empty() {
        error!("Secret key is empty; rejecting signed request.");
        return false;
    }
    match signature_type {
        SignatureType::XHubSignature => {
            verify_hmac_hex::<Hmac<Sha1>>(secret_key, payload, expected_signature, "sha1=")
        }
        SignatureType::XHubSignature256 => {
            verify_hmac_hex::<Hmac<Sha256>>(secret_key, payload, expected_signature, "sha256=")
        }
        SignatureType::XGitlabToken => expected_signature
            .as_bytes()
            .ct_eq(secret_key.as_bytes())
            .into(),
        SignatureType::XLineSignature => {
            let Ok(sig_bytes) = general_purpose::STANDARD.decode(expected_signature) else {
                return false;
            };
            let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes()) else {
                return false;
            };
            mac.update(payload.as_bytes());
            mac.verify_slice(&sig_bytes).is_ok()
        }
    }
}

/// Decides whether a webhook may be relayed.
///
/// With a configured secret, at least one supported signature header must be
/// present and every supported signature header present must be valid.
/// Without a secret, only unsigned requests are accepted.
fn verify_webhook(
    headers: &actix_web::http::header::HeaderMap,
    payload: &str,
    secret_key: Option<&str>,
) -> bool {
    let mut found = false;
    for (name, signature_type) in SIGNATURE_HEADERS {
        for value in headers.get_all(name) {
            found = true;
            let (Some(secret), Ok(value_str)) = (secret_key, value.to_str()) else {
                return false;
            };
            if !validate_signature(signature_type, value_str, payload, secret) {
                return false;
            }
        }
    }
    found || secret_key.is_none()
}

fn has_signature_header(headers: &actix_web::http::header::HeaderMap) -> bool {
    SIGNATURE_HEADERS
        .iter()
        .any(|(name, _)| headers.contains_key(*name))
}

/// Headers whose values are credentials and must never be logged.
const SENSITIVE_HEADERS: [&str; 7] = [
    "authorization",
    "cookie",
    "x-gitlab-token",
    "x-hub-signature",
    "x-hub-signature-256",
    "x-line-signature",
    "proxy-authorization",
];

fn redact_headers(headers: &HashMap<String, String>) -> std::collections::BTreeMap<&str, &str> {
    headers
        .iter()
        .map(|(k, v)| {
            let sensitive = SENSITIVE_HEADERS.contains(&k.to_ascii_lowercase().as_str());
            (
                k.as_str(),
                if sensitive { "[REDACTED]" } else { v.as_str() },
            )
        })
        .collect()
}

fn first_header<'a>(headers: &'a HashMap<String, String>, names: &[&str]) -> &'a str {
    names
        .iter()
        .find_map(|n| headers.get(*n))
        .map_or("-", String::as_str)
}

/// Bodies are logged only on explicit opt-in, and never for end-to-end
/// encrypted channels.
fn should_log_body(log_payloads: bool, encrypted_channel: bool) -> bool {
    log_payloads && !encrypted_channel
}

/// Default request body cap: GitHub's maximum webhook payload size (25 MiB).
const DEFAULT_MAX_BODY_BYTES: usize = 25 * 1024 * 1024;

/// Reads the whole body, or returns `Ok(None)` as soon as it exceeds `limit`
/// so oversized uploads are never buffered in full.
async fn read_body_limited<S, E>(stream: &mut S, limit: usize) -> Result<Option<Vec<u8>>, E>
where
    S: futures_util::Stream<Item = Result<web::Bytes, E>> + Unpin,
{
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
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

    let declared_len = req
        .headers()
        .get(actix_web::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared_len.is_some_and(|n| n > data.max_body_bytes) {
        warn!(
            "Rejected webhook: channel={} reason=\"body too large\" content_length={} limit={}",
            id,
            declared_len.unwrap_or(0),
            data.max_body_bytes
        );
        return Ok(HttpResponse::PayloadTooLarge().body("Payload too large"));
    }

    let body_bytes = match read_body_limited(&mut payload, data.max_body_bytes).await? {
        Some(bytes) => bytes,
        None => {
            warn!(
                "Rejected webhook: channel={} reason=\"body too large\" limit={}",
                id, data.max_body_bytes
            );
            return Ok(HttpResponse::PayloadTooLarge().body("Payload too large"));
        }
    };
    // Decode once after reading so multi-byte characters split across chunks stay intact.
    let body_data = String::from_utf8_lossy(&body_bytes).into_owned();

    let secret_key = get_secret_key(&id).map_err(|e| {
        error!("Failed to read secret key for channel '{}': {}", id, e);
        actix_web::error::ErrorInternalServerError("Failed to load channel secret")
    })?;
    let valid = verify_webhook(req.headers(), &body_data, secret_key.as_deref());

    // Extract headers into a HashMap<String, String>
    let mut headers = HashMap::new();
    for (key, value) in req.headers().iter() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(key.to_string(), value_str.to_string());
        } else {
            warn!("Warning: Header value for '{}' is not valid UTF-8.", key);
        }
    }

    // Create the Payload instance
    let payload = Payload {
        body: body_data,
        headers: serde_json::to_string(&headers).unwrap(),
    };

    let signed = has_signature_header(req.headers());
    if !valid {
        let reason = match (secret_key.is_some(), signed) {
            (true, false) => "missing signature",
            (false, _) => "signature sent but channel has no secret",
            (true, true) => "invalid signature",
        };
        warn!("Rejected webhook: channel={} reason=\"{}\"", id, reason);
        return Err(actix_web::error::ErrorUnauthorized("Invalid signature"));
    }

    let sender = get_broadcast_sender(id.clone(), data.channels.clone()).ok();
    info!(
        "Received webhook: channel={} event={} delivery={} bytes={} sig={} subscribers={}",
        id,
        first_header(&headers, &["x-github-event", "x-gitlab-event"]),
        first_header(&headers, &["x-github-delivery", "x-gitlab-event-uuid"]),
        payload.body.len(),
        if signed { "ok" } else { "none" },
        sender.as_ref().map_or(0, |s| s.receiver_count()),
    );
    if log_enabled!(log::Level::Debug) {
        debug!(
            "Webhook headers: channel={} headers={:?}",
            id,
            redact_headers(&headers)
        );
        let encrypted = PathBuf::from(format!("pem/{}", id)).exists();
        if should_log_body(data.log_payloads, encrypted) {
            debug!("Webhook body: channel={} body={}", id, payload.body);
        }
    }

    // A channel without subscribers is not an error, so webhook validation
    // requests succeed even when nobody is listening yet.
    match sender {
        Some(sender) => {
            // Send the payload to all subscribers of the broadcast channel.
            if let Err(e) = sender.send(payload) {
                error!("Failed to send payload to broadcast channel: {}", e);
                return Err(actix_web::error::ErrorInternalServerError(
                    "Failed to broadcast payload",
                ));
            }
        }
        None => {
            info!(
                "Accepted webhook for channel '{}' (no active subscribers)",
                id
            );
        }
    }
    Ok(HttpResponse::Ok().finish())
}

async fn not_found(req: HttpRequest) -> impl Responder {
    // Don't log the full request: its headers may carry credentials.
    error!("{} {} Not Found", req.method(), req.path());
    HttpResponse::NotFound().body(format!("<h1>404 Not Found</h1>"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Environment variable configuration for host and port
    let host = std::env::var("HOST").unwrap_or("0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or("3000".to_string());
    let addr = format!("{}:{}", host, port);
    let admin_token = admin_token(
        std::env::var("AUTH_USER").ok(),
        std::env::var("AUTH_PASS").ok(),
    );
    if admin_token.is_none() {
        warn!("AUTH_PASS is unset or empty; /admin endpoint is disabled");
    }
    let log_payloads = std::env::var("LOG_PAYLOADS").is_ok_and(|v| v == "1");
    let max_body_bytes = match std::env::var("MAX_BODY_BYTES") {
        Err(_) => DEFAULT_MAX_BODY_BYTES,
        Ok(v) => match v.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                warn!(
                    "Invalid MAX_BODY_BYTES '{}'; using default {}",
                    v, DEFAULT_MAX_BODY_BYTES
                );
                DEFAULT_MAX_BODY_BYTES
            }
        },
    };
    if log_payloads {
        warn!("LOG_PAYLOADS=1: webhook bodies of unencrypted channels are logged at debug level");
    }
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
        admin_token: admin_token.clone(),
        log_payloads,
        max_body_bytes,
        public_path: public_path.clone(),
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
    use aes_gcm::{Key, Nonce};
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
        let calculated_signature = general_purpose::STANDARD.encode(signature_bytes);

        let expected_signature = &calculated_signature;

        let signature_type = SignatureType::XLineSignature;
        let valid = validate_signature(signature_type, expected_signature, payload, secret_key);
        assert!(
            valid,
            "X-Line-Signature validation failed: calculated '{}', expected '{}'",
            calculated_signature, expected_signature
        );
    }

    #[test]
    fn test_verify_webhook_policy() {
        use actix_web::test::TestRequest;

        let secret = "secret";
        let body = "payload";
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body.as_bytes());
        let good256 = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        let bad256 = format!("sha256={}", "0".repeat(64));

        let req = |hs: &[(&str, &str)]| {
            let mut r = TestRequest::default();
            for (k, v) in hs {
                r = r.insert_header((*k, *v));
            }
            r.to_http_request()
        };

        // Secret configured: unsigned requests must be rejected.
        assert!(!verify_webhook(req(&[]).headers(), body, Some(secret)));
        assert!(!verify_webhook(
            req(&[("x-github-event", "push")]).headers(),
            body,
            Some(secret)
        ));
        assert!(verify_webhook(
            req(&[("x-hub-signature-256", &good256)]).headers(),
            body,
            Some(secret)
        ));
        assert!(!verify_webhook(
            req(&[("x-hub-signature-256", &bad256)]).headers(),
            body,
            Some(secret)
        ));
        // A valid header must not mask an invalid one.
        assert!(!verify_webhook(
            req(&[
                ("x-hub-signature-256", &good256),
                ("x-gitlab-token", "wrong")
            ])
            .headers(),
            body,
            Some(secret)
        ));
        assert!(!verify_webhook(
            req(&[("x-gitlab-token", "secre")]).headers(),
            body,
            Some(secret)
        ));

        // No secret configured: unsigned passes, signed is rejected.
        assert!(verify_webhook(req(&[]).headers(), body, None));
        assert!(!verify_webhook(
            req(&[("x-hub-signature-256", &good256)]).headers(),
            body,
            None
        ));
    }

    #[test]
    fn test_admin_token_requires_password() {
        // No default credentials: unset or empty password disables /admin.
        assert_eq!(admin_token(None, None), None);
        assert_eq!(admin_token(Some("admin".into()), None), None);
        assert_eq!(admin_token(Some("admin".into()), Some("".into())), None);
        assert_eq!(
            admin_token(Some("admin".into()), Some("s3cret".into())),
            Some(general_purpose::STANDARD.encode("admin:s3cret"))
        );
        assert_eq!(
            admin_token(None, Some("s3cret".into())),
            Some(general_purpose::STANDARD.encode("user:s3cret"))
        );
    }

    #[test]
    fn test_is_admin_authorized() {
        use actix_web::test::TestRequest;

        let expected = general_purpose::STANDARD.encode("admin:s3cret");
        let with = |v: &str| {
            TestRequest::default()
                .insert_header(("Authorization", v))
                .to_http_request()
        };
        assert!(is_admin_authorized(
            &with(&format!("Basic {}", expected)),
            &expected
        ));
        assert!(!is_admin_authorized(
            &with(&format!(
                "Basic {}",
                general_purpose::STANDARD.encode("admin:")
            )),
            &expected
        ));
        assert!(!is_admin_authorized(
            &TestRequest::default().to_http_request(),
            &expected
        ));
    }

    #[test]
    fn test_redact_headers() {
        let headers: HashMap<String, String> = [
            ("x-gitlab-token", "topsecret"),
            ("Authorization", "Basic dXNlcjpwYXNz"),
            ("x-hub-signature-256", "sha256=abc"),
            ("x-line-signature", "abc="),
            ("x-github-event", "push"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let redacted = redact_headers(&headers);
        assert_eq!(redacted["x-gitlab-token"], "[REDACTED]");
        assert_eq!(redacted["Authorization"], "[REDACTED]");
        assert_eq!(redacted["x-hub-signature-256"], "[REDACTED]");
        assert_eq!(redacted["x-line-signature"], "[REDACTED]");
        assert_eq!(redacted["x-github-event"], "push");
        let rendered = format!("{:?}", redacted);
        assert!(!rendered.contains("topsecret") && !rendered.contains("dXNlcjpwYXNz"));
    }

    #[test]
    fn test_should_log_body() {
        assert!(!should_log_body(false, false));
        assert!(!should_log_body(false, true));
        // Opt-in never applies to end-to-end encrypted channels.
        assert!(!should_log_body(true, true));
        assert!(should_log_body(true, false));
    }

    #[actix_web::test]
    async fn test_read_body_limited() {
        use futures_util::stream;

        let chunks = || {
            stream::iter(vec![
                Ok::<_, std::convert::Infallible>(web::Bytes::from_static(b"hello ")),
                Ok(web::Bytes::from_static(b"world")),
            ])
        };
        assert_eq!(
            read_body_limited(&mut chunks(), 11).await.unwrap(),
            Some(b"hello world".to_vec())
        );
        assert_eq!(read_body_limited(&mut chunks(), 10).await.unwrap(), None);
        // Stops at the chunk that crosses the limit instead of draining the stream.
        let mut s = chunks();
        assert_eq!(read_body_limited(&mut s, 5).await.unwrap(), None);
        assert_eq!(
            s.next().await.map(|c| c.unwrap()),
            Some(web::Bytes::from_static(b"world"))
        );
    }

    #[test]
    fn test_read_channel_auth_token() {
        let channel_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let unique = format!(
            "webhook-relay-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let temp_root = std::env::temp_dir().join(unique);
        let auth_dir = temp_root.join("auth");
        std::fs::create_dir_all(&auth_dir).unwrap();
        std::fs::write(auth_dir.join(channel_id), "dXNlcjpwYXNz\n").unwrap();

        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp_root).unwrap();
        let token = read_channel_auth_token(channel_id).unwrap();
        std::env::set_current_dir(old_cwd).unwrap();

        assert_eq!(token, Some("dXNlcjpwYXNz".to_string()));
        std::fs::remove_dir_all(temp_root).unwrap();
    }

    #[test]
    fn test_extract_basic_token_from_request() {
        use actix_web::test::TestRequest;

        let req = TestRequest::default()
            .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
            .to_http_request();

        let token = extract_basic_token(&req);
        assert_eq!(token, Some("dXNlcjpwYXNz".to_string()));
    }
}
