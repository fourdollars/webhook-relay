use actix_web::{get, post, web, App, Error, HttpResponse, HttpServer};
use actix_web::body::BodyStream;
use base64::Engine;
use futures_util::stream::StreamExt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast::{self, Sender};
use tokio_stream::wrappers::BroadcastStream;

/// Type alias for our global channels HashMap.
/// The HashMap key is the channel ID (String), and the value is a broadcast::Sender<String>
/// used for sending SSE messages.
type GlobalChannels = Arc<Mutex<HashMap<String, Sender<String>>>>;

/// Formats a message into an SSE event string.
fn format_sse_event(data: &str) -> String {
    let data = Engine::encode(&base64::engine::general_purpose::STANDARD, data);
    format!("event: webhook\ndata: {}\n\n", data)
}

// --- Channel Management Functions ---

/// Gets or creates a new SSE stream channel (broadcast mode).
/// This function is called when a client connects to `/relay/{id}`.
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
        let (tx, _rx) = broadcast::channel::<String>(1024);
        println!("New broadcast channel '{}' created.", id);
        tx
    });

    // Subscribe a new receiver from the existing or newly created sender.
    // Each new client will get its own receiver here, ensuring all receive messages.
    let rx = sender.subscribe();
    println!("Client subscribed to channel '{}'.", id);

    // Convert the BroadcastStream into a `Stream<Item = Result<Bytes, Error>>`,
    // which is the expected Item type for `actix_web::body::BodyStream`.
    BroadcastStream::new(rx).map(move |msg_result| {
        let formatted_data = match msg_result {
            Ok(data) => format_sse_event(&data),
            Err(e) => {
                // Handle receive errors (e.g., Lagged error if receiver falls too far behind)
                eprintln!("Error receiving message for channel '{}': {}", id, e);
                format_sse_event(&format!("Error: {}", e)) // Send an error message to the client
            }
        };
        // Convert the String to web::Bytes as required by BodyStream
        Ok(web::Bytes::from(formatted_data))
    })
}

/// Gets the existing SSE stream channel's sender.
/// This is called when a POST request is received to send a message to a channel.
fn get_broadcast_sender(id: String, channels: GlobalChannels) -> Result<Sender<String>, Error> {
    let map = channels.lock().map_err(|e| {
        eprintln!("Failed to lock channels: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to access channels")
    })?;

    map.get(&id)
        .cloned() // Get an owned copy of the Sender
        .ok_or_else(|| {
            eprintln!("Broadcast channel '{}' not found for sending.", id);
            actix_web::error::ErrorNotFound(format!("Broadcast channel '{}' not found", id))
        })
}

// --- Actix-Web Route Handlers ---

/// Simple index page handler.
#[get("/")]
async fn index() -> HttpResponse {
    HttpResponse::Ok().body("Hello from SSE broadcast relay service!")
}

/// Handles GET requests to receive messages from a specific SSE channel.
#[get("/relay/{id}")]
async fn relay_get(
    id: web::Path<String>,
    channels_data: web::Data<GlobalChannels>, // Injects the global channels data
) -> HttpResponse {
    let mut res_builder = HttpResponse::Ok();
    res_builder
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"));

    // Wrap the Stream returned by `get_or_create_stream_channel_stream` with `BodyStream`.
    res_builder.body(BodyStream::new(
        get_or_create_stream_channel_stream(id.into_inner(), channels_data.get_ref().clone()),
    ))
}

/// Handles POST requests to broadcast a message to a specific SSE channel.
#[post("/relay/{id}")]
async fn relay_post(
    id: web::Path<String>,
    mut payload: web::Payload,
    channels_data: web::Data<GlobalChannels>, // Injects the global channels data
) -> Result<HttpResponse, Error> {
    let sender = get_broadcast_sender(id.into_inner(), channels_data.get_ref().clone())?;
    let mut data = String::new();

    // Iterate over the payload chunks to read the incoming data.
    while let Some(chunk_result) = payload.next().await {
        let chunk = chunk_result?; // `chunk` is now of type `web::Bytes`
        data.push_str(&String::from_utf8_lossy(&chunk));
    }

    // Send the message to all subscribers of the broadcast channel.
    // `sender.send()` returns an `Err` if all receivers have been dropped or the channel is closed.
    if let Err(e) = sender.send(data) {
        eprintln!("Failed to send message to broadcast channel: {}", e);
        // In a more robust application, you might want to remove the channel from the HashMap here
        return Err(actix_web::error::ErrorInternalServerError(
            "Failed to broadcast message",
        ));
    }
    Ok(HttpResponse::Ok().finish())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Environment variable configuration for host and port
    let host = std::env::var("HOST").unwrap_or("0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or("3000".to_string());
    let addr = format!("{}:{}", host, port);

    // Initialize the global channels HashMap.
    // Arc enables shared ownership across threads, Mutex ensures exclusive access for modification.
    let channels: GlobalChannels = Arc::new(Mutex::new(HashMap::new()));

    println!("Starting Actix-Web broadcast SSE relay service on http://{}", addr);

    HttpServer::new(move || {
        // Use .app_data() to add the `channels` data to the application state.
        // `.clone()` is necessary because the closure is called multiple times (once per worker).
        App::new()
            .app_data(web::Data::new(channels.clone())) // Pass channels to the App
            .service(index)
            .service(relay_get)
            .service(relay_post)
    })
    .bind(addr)?
    .run()
    .await
}
