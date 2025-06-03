use actix_web::body::BodyStream;
use actix_web::{get, post, web, App, Error, HttpResponse, HttpRequest, HttpServer, Responder, middleware::NormalizePath};
use base64::Engine;
use futures_util::stream::StreamExt;
use hmac::{Hmac, Mac};
use serde::{Serialize, Deserialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast::{self, Sender};
use tokio_stream::wrappers::BroadcastStream;

#[macro_use]
extern crate log;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Message {
    payload: String,
    headers: HashMap<String, String>,
}

type GlobalChannels = Arc<Mutex<HashMap<String, Sender<Message>>>>;

fn format_webhook_event(data: &str) -> String {
    let data = Engine::encode(&base64::engine::general_purpose::STANDARD, data);
    format!("event: webhook\ndata: {}\n\n", data)
}

fn format_ping_event(data: &str) -> String {
    format!("event: ping\ndata: {}\nid: {}\n\n", data, std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_millis())
}

fn format_error_event(data: &str) -> String {
    format!("event: error\ndata: {}\n\n", data)
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
        // Buffer size of 1024 means up to 1024 messages can be stored if not received.
        // If the buffer is full, sending will return an Err(SendError::Full).
        let (tx, _rx) = broadcast::channel::<Message>(1024);
        info!("New broadcast channel '{}' created.", id);
        tx
    });

    // Subscribe a new receiver from the existing or newly created sender.
    // Each new client will get its own receiver here, ensuring all receive messages.
    let rx = sender.subscribe();
    info!("Client subscribed to channel '{}'.", id);

    // Convert the BroadcastStream into a `Stream<Item = Result<Bytes, Error>>`,
    // which is the expected Item type for `actix_web::body::BodyStream`.
    BroadcastStream::new(rx).map(move |msg_result| {
        let formatted_bytes = match msg_result {
            Ok(msg) => {
                let json_string = serde_json::to_string(&msg).unwrap_or_else(|e| {
                        debug!("Failed to serialize Message: {}", e);
                        // Return an error JSON if serialization fails
                        format!(r#"{{"error": "Failed to serialize message: {}"}}"#, e)
                    });
                if msg.headers.len() > 0 {
                    format_webhook_event(&json_string)
                } else {
                    format_ping_event(msg.payload.as_str())
                }
            },
            Err(e) => {
                // Handle receive errors (e.g., Lagged error if receiver falls too far behind)
                error!("Error receiving message for channel '{}': {}", id, e);
                format_error_event(&format!("Error receiving message: {}", e))
            }
        };
        // Convert the String to web::Bytes as required by BodyStream
        Ok(web::Bytes::from(formatted_bytes))
    })
}

/// Gets the existing SSE stream channel's sender.
/// This is called when a POST request is received to send a message to a channel.
fn get_broadcast_sender(id: String, channels: GlobalChannels) -> Result<Sender<Message>, Error> {
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

fn list_channels_page(channels: GlobalChannels) -> String {
    let mut content = String::new();
    let map = channels.lock().unwrap();
    for (id, sender) in map.iter() {
        content.push_str(&format!("<li><a href=\"/{}\">{}/{}</a></li>", id, id, sender.receiver_count()));
    }
    content
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("<h1>Webhook Relay</h1>")
}

#[get("/admin")]
async fn admin(
    req: HttpRequest,
    credentials: web::Data<(String, String)>,
    channels_data: web::Data<GlobalChannels>,
) -> HttpResponse {
    let auth = req.headers().get("Authorization");

    if auth.is_none() {
        let mut response = HttpResponse::Unauthorized().finish();
        response.headers_mut().insert(
            actix_web::http::header::WWW_AUTHENTICATE,
            actix_web::http::header::HeaderValue::from_static("Basic realm=\"401\""),
        );
        return response;
    }

    let (user, pass) = credentials.get_ref();
    if let Some(auth) = auth {
        let auth = auth.to_str().unwrap_or("");
        if auth == format!("Basic {}", Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{}:{}", user, pass))) {
            let content = format!("<html><body><h1>Channels</h1><ul>{}</ul></body></html>", list_channels_page(channels_data.get_ref().clone()));
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
async fn relay_get(
    id: web::Path<String>,
    channels_data: web::Data<GlobalChannels>,
) -> HttpResponse {
    if id.len() != 40 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest().body("Invalid channel ID");
    }
    let mut res_builder = HttpResponse::Ok();
    res_builder
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"));

    res_builder.body(BodyStream::new(
        get_or_create_stream_channel_stream(id.into_inner(), channels_data.get_ref().clone()),
    ))
}

enum SignatureType {
    XHubSignature,
    XGitlabToken,
    XLineSignature,
}

fn read_secret_key(id: &str) -> String {
    let secret_path = format!("secret/{}", id);
    std::fs::read_to_string(&secret_path).unwrap_or_else(|e| {
        error!("Failed to read secret key: {}", e);
        "".to_string()
    })
}

fn validate_signature(signature_type: SignatureType, expected_signature: &str, payload: &str, secret_key: &str) -> bool {
    if secret_key.is_empty() {
        error!("Error: Secret key is empty for channel '{}'.", expected_signature);
        return false;
    }
    match signature_type {
        SignatureType::XHubSignature => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret_key.as_bytes()).expect("HMAC can take any key size");
            mac.update(payload.as_bytes());
            let signature_bytes = mac.finalize().into_bytes();
            let signature = format!("sha1={}", hex::encode(signature_bytes));
            if signature != expected_signature {
                return false;
            }
        },
        SignatureType::XGitlabToken => {
            if expected_signature != secret_key {
                return false;
            }
        },
        SignatureType::XLineSignature => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes()).expect("HMAC can take any key size");
            mac.update(payload.as_bytes());
            let signature_bytes = mac.finalize().into_bytes();
            let signature = format!("sha256={}", Engine::encode(&base64::engine::general_purpose::STANDARD, signature_bytes));
            if signature != expected_signature {
                return false;
            }
        },
    };
    true
}

/// Handles POST requests to broadcast a message to a specific SSE channel.
#[post("/{id}")]
async fn relay_post(
    req: HttpRequest,
    id: web::Path<String>,
    mut payload: web::Payload,
    channels_data: web::Data<GlobalChannels>, // Injects the global channels data
) -> Result<HttpResponse, Error> {
    if id.len() != 40 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(HttpResponse::BadRequest().body("Invalid channel ID"));
    }
    let sender = get_broadcast_sender(id.clone(), channels_data.get_ref().clone())?;
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
                "x-hub-signature" => valid = validate_signature(SignatureType::XHubSignature, value_str, &data, &read_secret_key(&id)),
                "x-gitlab-token" => valid = validate_signature(SignatureType::XGitlabToken, value_str, &data, &read_secret_key(&id)),
                "x-line-signature" => valid = validate_signature(SignatureType::XLineSignature, value_str, &data, &read_secret_key(&id)),
                _ => (),
            }
        } else {
            warn!("Warning: Header value for '{}' is not valid UTF-8.", key);
        }
    }

    // Create the Message instance
    let message = Message {
        payload: data,
        headers,
    };

    info!("Received: {:#?}", message);

    if !valid {
        return Err(actix_web::error::ErrorUnauthorized("Invalid signature"));
    }

    // Send the message to all subscribers of the broadcast channel.
    // `sender.send()` returns an `Err` if all receivers have been dropped or the channel is closed.
    if let Err(e) = sender.send(message) {
        error!("Failed to send message to broadcast channel: {}", e);
        // In a more robust application, you might want to remove the channel from the HashMap here
        return Err(actix_web::error::ErrorInternalServerError(
            "Failed to broadcast message",
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

    // Initialize the global channels HashMap.
    // Arc enables shared ownership across threads, Mutex ensures exclusive access for modification.
    let channels: GlobalChannels = Arc::new(Mutex::new(HashMap::new()));

    info!("Starting webhook relay service on http://{}", addr);

    let channels_for_tokio = channels.clone(); // Clone for the tokio::spawn block
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(7500));
        loop {
            interval.tick().await;
            let channels_clone_inner = channels_for_tokio.clone(); // Clone for the inner tokio::spawn
            tokio::spawn(async move {
                let mut channels_guard = channels_clone_inner.lock().unwrap(); // Get a mutable lock

                // Collect IDs to remove first to avoid issues with mutable and immutable borrows
                let mut ids_to_remove = Vec::new();
                for (id, sender) in channels_guard.iter() {
                    if sender.receiver_count() == 0 {
                        ids_to_remove.push(id.clone()); // Store the ID to remove later
                    } else {
                        _ = sender.send(Message {
                            payload: format!("{}", sender.receiver_count()),
                            headers: HashMap::new(),
                        });
                    }
                }

                // Now remove the collected IDs
                for id in ids_to_remove {
                    channels_guard.remove(&id);
                    info!("Removed channel {}", id);
                }
            }).await.unwrap();
        }
    });
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(channels.clone()))
            .app_data(web::Data::new((user.clone(), pass.clone())))
            .wrap(NormalizePath::new(actix_web::middleware::TrailingSlash::Trim))
            .service(favicon)
            .service(index)
            .service(admin)
            .service(relay_get)
            .service(relay_post)
            .default_service(web::to(not_found))
    })
    .bind(addr)?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(valid, "X-Hub-Signature validation failed: calculated '{}', expected '{}'", calculated_signature, expected_signature);
    }
    #[test]
    fn test_x_gitlab_token() {
        let secret_key = "secret";
        let payload = "payload";

        let valid = validate_signature(SignatureType::XGitlabToken, secret_key, payload, secret_key);
        assert!(valid, "X-Gitlab-Token validation failed: calculated '{}', expected '{}'", secret_key, secret_key);
    }
    #[test]
    fn test_x_line_signature() {
        let secret_key = "secret";
        let payload = "payload";

        let mut mac = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes())
            .expect("HMAC can take any key size in test");
        mac.update(payload.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let calculated_signature = format!("sha256={}", Engine::encode(&base64::engine::general_purpose::STANDARD, signature_bytes));

        let expected_signature = &calculated_signature;

        let signature_type = SignatureType::XLineSignature;
        let valid = validate_signature(signature_type, expected_signature, payload, secret_key);
        assert!(valid, "X-Line-Signature validation failed: calculated '{}', expected '{}'", calculated_signature, expected_signature);
    }
}
