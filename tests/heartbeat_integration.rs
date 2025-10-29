// Integration tests for heartbeat and reconnection functionality

use std::process::{Command, Child};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_client_reconnection_on_server_restart() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let private_key_path = format!("{}/tests/private_key.pem", manifest_dir);

    // Start the server on a different port to avoid conflicts
    let mut server = start_server(&manifest_dir, "4003").await;
    
    // Start the client
    let mut client = start_client(&manifest_dir, "4003", &private_key_path).await;

    // Wait for initial connection
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Kill the server to simulate disconnection
    server.kill().expect("Failed to kill server");
    
    // Wait a bit for client to detect disconnection
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Start the server again
    server = start_server(&manifest_dir, "4003").await;

    // Wait for reconnection
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Send a webhook to verify connection is working
    let payload = r#"{"body":"{\"msg\":\"reconnection_test\"}","headers":"{}"}"#;
    let http_client = reqwest::Client::new();
    let res = http_client
        .post("http://localhost:4003/0123456789abcdef0123456789abcdef01234567")
        .body(payload)
        .send()
        .await
        .expect("failed to send webhook");
    
    assert!(res.status().is_success());

    // Cleanup
    server.kill().ok();
    client.kill().ok();
}

#[tokio::test]
async fn test_client_exit_on_max_reconnection_attempts() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let private_key_path = format!("{}/tests/private_key.pem", manifest_dir);

    // Start the server briefly then kill it immediately
    let mut server = start_server(&manifest_dir, "4004").await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    server.kill().expect("Failed to kill server");

    // Start the client - it should try to reconnect and eventually give up
    let mut client = start_client(&manifest_dir, "4004", &private_key_path).await;

    // Wait for client to exhaust reconnection attempts and exit
    // With exponential backoff (1, 2, 4, 8, 16s) and 5 attempts, this should take about 31 seconds
    let client_result = timeout(Duration::from_secs(45), async {
        client.wait().expect("Failed to wait for client")
    }).await;

    match client_result {
        Ok(exit_status) => {
            // Client should exit with code 1 (connection failure)
            assert!(!exit_status.success());
            if let Some(code) = exit_status.code() {
                assert_eq!(code, 1, "Client should exit with code 1 on connection failure");
            }
        }
        Err(_) => {
            // Timeout - client didn't exit as expected
            client.kill().ok();
            panic!("Client did not exit within expected timeframe");
        }
    }
}

async fn start_server(manifest_dir: &str, port: &str) -> Child {
    Command::new("cargo")
        .args(["run", "--package", "webhook-relay"])
        .env("PORT", port)
        .env("RUST_LOG", "error") // Reduce log noise
        .current_dir(manifest_dir)
        .spawn()
        .expect("failed to start server")
}

async fn start_client(manifest_dir: &str, port: &str, private_key_path: &str) -> Child {
    let url = format!("http://localhost:{}/0123456789abcdef0123456789abcdef01234567", port);
    
    Command::new("cargo")
        .args(["run", "--package", "relayd", &url, private_key_path])
        .env("RUST_LOG", "info")
        .current_dir(manifest_dir)
        .spawn()
        .expect("failed to start client")
}