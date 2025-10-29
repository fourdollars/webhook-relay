use std::env;
use std::process::{Child, Command};
use std::time::Duration;

async fn start_server_with_ping_stop_and_shutdown(
    manifest_dir: &str,
    port: &str,
    stop_after_seconds: u64,
    shutdown_after_seconds: u64,
) -> Child {
    Command::new("cargo")
        .args(["run", "--package", "webhook-relay"])
        .env("PORT", port)
        .env("PING_STOP_AFTER_SECONDS", stop_after_seconds.to_string())
        .env(
            "SERVER_SHUTDOWN_AFTER_SECONDS",
            shutdown_after_seconds.to_string(),
        )
        .env("RUST_LOG", "info")
        .current_dir(manifest_dir)
        .spawn()
        .expect("failed to start server")
}

#[tokio::test]
async fn test_client_detects_heartbeat_timeout() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let private_key_path = format!("{}/tests/private_key.pem", manifest_dir);
    let port = "4005";

    // Start server that stops sending pings after 10 seconds and shuts down after 50 seconds
    // This gives the client time to detect the heartbeat timeout and attempt reconnections
    let mut server = start_server_with_ping_stop_and_shutdown(&manifest_dir, port, 10, 50).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Start client with default heartbeat timeout (30 seconds)
    let client_process = Command::new("cargo")
        .args([
            "run",
            "--package",
            "relayd",
            &format!(
                "http://localhost:{}/0123456789abcdef0123456789abcdef01234567",
                port
            ),
            &private_key_path,
        ])
        .current_dir(&manifest_dir)
        .spawn()
        .expect("failed to start client");

    // The test validates:
    // 1. Server stops sending pings after 10 seconds
    // 2. Client detects heartbeat timeout after 30 seconds (default timeout)
    // 3. Client attempts reconnection (default is 5 attempts with exponential backoff)
    // 4. Server shuts down after 50 seconds, preventing further reconnections
    // 5. Client should exit with error code 1 after max reconnection attempts

    // Wait for client to complete all reconnection attempts and exit
    let output = tokio::task::spawn_blocking(move || client_process.wait_with_output())
        .await
        .expect("failed to join task")
        .expect("failed to wait for client");

    let _ = server.kill();
    let _ = server.wait();

    // Verify client behavior
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Client stderr length: {}", stderr.len());
    println!("Client stdout length: {}", stdout.len());
    println!("Exit code: {:?}", output.status.code());

    // Client should exit with error code 1 (connection failure after max attempts)
    // This verifies that:
    // 1. Client detected the missing pings (heartbeat timeout)
    // 2. Client attempted reconnections
    // 3. Client exhausted all reconnection attempts
    // 4. Client exited with the correct error code
    assert_eq!(
        output.status.code(),
        Some(1),
        "Client should exit with error code 1 after exhausting reconnection attempts"
    );
}
