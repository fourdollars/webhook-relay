# Project Context

## Purpose
A secure SSE (Server-Sent Events) webhook relay server that enables real-time webhook forwarding with cryptographic security features. The system consists of a Rust-based HTTP server that receives webhooks and broadcasts them to connected SSE clients, with support for signature validation and asymmetric/symmetric payload encryption.

## Tech Stack
- **Backend**: Rust with Actix Web framework
- **Client**: Rust with eventsource-client library
- **Cryptography**: RSA (asymmetric), AES-GCM (symmetric), HMAC-SHA256/SHA1 signature validation
- **Testing**: Cargo test with integration tests, tokio for async testing
- **Build**: Cargo workspace with server and client binaries

## Project Conventions

### Code Style
- Follow standard Rust formatting (rustfmt)
- Use `cargo clippy` for linting
- Edition 2024 for both server and client
- Prefer `log` crate for logging with env_logger
- Use `Result<T, Error>` for error handling

### Architecture Patterns
- Actix Web for HTTP server with broadcast channels for SSE
- Global channel manager using Arc<Mutex<HashMap>> for thread-safe access
- Async/await pattern throughout with tokio runtime
- Separation of concerns: server binary (webhook-relay) and client binary (relayd)
- Cryptographic operations isolated in dedicated functions

### Testing Strategy
- Unit tests for cryptographic functions and signature validation
- Integration tests for server-client interaction in `tests/` directory
- Test-specific RSA key pairs in `tests/private_key.pem` and `tests/public_key.pem`
- Use of reqwest for HTTP testing and tokio for async test orchestration

### Git Workflow
- Single main branch development
- Standard commit messages
- Each capability should be independently testable

## Domain Context
- **Webhook Relay**: Receives HTTP POST webhooks and forwards them via SSE to connected clients
- **Channel Management**: Each unique ID creates a broadcast channel; channels auto-cleanup when no subscribers
- **Signature Validation**: Supports X-Hub-Signature (GitHub), X-GitLab-Token, and X-Line-Signature
- **Encryption**: Optional asymmetric encryption for payload security using RSA + AES-GCM
- **Heartbeat**: Server sends periodic "ping" events to maintain SSE connections

## Important Constraints
- RSA key size limitations for asymmetric encryption payload size
- SSE connection management requires careful cleanup to prevent memory leaks
- Signature validation must support multiple webhook providers (GitHub, GitLab, Line)
- Encryption is optional and falls back to base64 encoding if keys unavailable

## External Dependencies
- Webhook providers: GitHub, GitLab, Line (signature formats)
- RSA public/private key infrastructure for encryption
- Environment variables for server configuration (HOST, PORT, AUTH_USER, AUTH_PASS)
- PEM format key files for cryptographic operations
