// Integration test for server/client interaction
// Requires starting the server, then the client connects and verifies the event flow

use std::process::Command;
use std::time::Duration;

#[tokio::test]
async fn test_server_client_interaction() {
    // Get the project root directory path
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let private_key_path = format!("{}/tests/private_key.pem", manifest_dir);

    // Start the server
    let mut server = Command::new("cargo")
        .args(["run", "--package", "webhook-relay"])
        .env("PORT", "4000")
        .env("RUST_LOG", "info")
        .current_dir(&manifest_dir)
        .spawn()
        .expect("failed to start server");

    // Wait for the server to start
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Start the client and connect to the server
    let mut client = Command::new("cargo")
        .args([
            "run",
            "--package",
            "relayd",
            "http://localhost:4000/0123456789abcdef0123456789abcdef01234567",
            &private_key_path,
        ])
        .current_dir(&manifest_dir)
        .spawn()
        .expect("failed to start client");

    // Wait for the client to connect
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send webhook event
    let payload = r#"{"body":"{\"msg\":\"hello\"}","headers":"{}"}"#;
    let http_client = reqwest::Client::new();
    let res = http_client
        .post("http://localhost:4000/0123456789abcdef0123456789abcdef01234567")
        .body(payload)
        .send()
        .await
        .expect("failed to send webhook");
    assert!(res.status().is_success());

    // Wait for the client to process
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Close client/server
    server.kill().ok();
    client.kill().ok();
}
