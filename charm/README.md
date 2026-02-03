# Webhook Relay Charm

A Juju Charm for deploying the webhook-relay service, a Server-Sent Events (SSE) webhook relay server implemented in Rust.

## Features

- **Two operational modes:**
  - **server**: Acts as a relay server accepting webhook POST requests and broadcasting them via SSE
  - **client**: Acts as a relay client connecting to a webhook server
  
- **Security features:**
  - HMAC signature validation (X-Hub-Signature, X-Gitlab-Token, X-Line-Signature)
  - Asymmetric encryption with RSA public/private keys
  - Channel-based message broadcasting

- **Operational features:**
  - Automatic channel cleanup
  - Heartbeat/ping mechanism
  - Configurable ping intervals

## Usage

### Deploy in server mode (server)

```bash
# Generate a channel ID (40-character SHA1 hash)
CHANNEL_ID=$(uuidgen | sha1sum | awk '{print $1}')

juju deploy webhook-relay
juju config webhook-relay mode=server
juju config webhook-relay port=3000
juju config webhook-relay channelId0="$CHANNEL_ID"
juju config webhook-relay secret0="your-secret-key-for-channel-0"
juju config webhook-relay key0="$(cat public_key_0.pem)"

# Your webhook URL will be: http://server:3000/$CHANNEL_ID
echo "Webhook URL: http://your-server:3000/$CHANNEL_ID"
```

### Deploy in client mode (client)

```bash
juju deploy webhook-relay relay-client
juju config relay-client mode=client
juju config relay-client url="http://webhook-server:3000/channel-id"
juju config relay-client secret="shared-secret"
juju config relay-client key="$(cat private_key.pem)"
```

## Configuration

### Common options

- `mode`: Operation mode - `webhook` (server) or `relayd` (client)

### Webhook mode options

- `host`: Host address to bind (default: "0.0.0.0")
- `port`: Port to bind (default: 3000)
- `auth-user`: Admin username for /admin endpoint (default: "admin")
- `auth-pass`: Admin password for /admin endpoint
- `public-path`: Public path prefix for the application
- `base-path`: Base path for webhook relay endpoints
- `ping-interval-ms`: Ping interval in milliseconds (default: 7500)
- `channelId0`-`channelId9`: Channel IDs (40-char hex SHA1) used as webhook URL paths (per channel)
- `secret0`-`secret9`: Secret keys for signature validation (per channel)
- `key0`-`key9`: RSA public keys for encryption (per channel, PEM format)

### Client mode options

- `url`: SSE endpoint URL to connect to (required)
- `forward`: HTTP POST URL to forward webhook payloads (optional). If specified, decrypted webhook payloads will be POSTed to this URL instead of stdout. Ping events are never forwarded.
- `secret`: Shared secret for signature validation
- `key`: RSA private key for decryption (PEM format)

## Channel Configuration

The server mode supports up to 10 channels (0-9), each with its own:
- **Channel ID**: 40-character hexadecimal SHA1 hash used as the webhook URL path
- **Secret key**: For HMAC signature validation
- **Public key**: For RSA encryption (optional)

### Generating Channel IDs

Channel IDs should be 40-character hexadecimal strings (SHA1 format):

```bash
# Using uuidgen and sha1sum
CHANNEL_ID=$(uuidgen | sha1sum | awk '{print $1}')

# Or using openssl
CHANNEL_ID=$(openssl rand -hex 20)

# Or using any unique identifier hashed with SHA1
echo "my-unique-channel-name" | sha1sum | awk '{print $1}'
```

### Example: Configuring Multiple Channels

```bash
# Channel 0 for GitHub webhooks
GITHUB_CHANNEL=$(uuidgen | sha1sum | awk '{print $1}')
juju config webhook-relay channelId0="$GITHUB_CHANNEL"
juju config webhook-relay secret0="github-webhook-secret"
juju config webhook-relay key0="$(cat github_public_key.pem)"
echo "GitHub webhook URL: http://your-server:3000/$GITHUB_CHANNEL"

# Channel 1 for GitLab webhooks
GITLAB_CHANNEL=$(uuidgen | sha1sum | awk '{print $1}')
juju config webhook-relay channelId1="$GITLAB_CHANNEL"
juju config webhook-relay secret1="gitlab-webhook-token"
juju config webhook-relay key1="$(cat gitlab_public_key.pem)"
echo "GitLab webhook URL: http://your-server:3000/$GITLAB_CHANNEL"
```

### Webhook URL Format

Once configured, webhook providers should send POST requests to:

```
http(s)://your-server:port/{channelId}
```

Where `{channelId}` is the 40-character hex string configured for that channel.

## Signature Validation

The webhook server validates incoming requests using these headers:

- `X-Hub-Signature`: GitHub-style HMAC-SHA1 signature
- `X-Gitlab-Token`: GitLab token validation
- `X-Line-Signature`: LINE HMAC-SHA256 signature

## Encryption

When a public key is configured for a channel:
1. Messages are encrypted using AES-256-GCM with a random symmetric key
2. The symmetric key is encrypted with the RSA public key
3. Clients with the corresponding private key can decrypt messages

## Development

### Building the charm

```bash
# Build Rust binaries
cargo build --release

# Copy binaries to charm
mkdir -p charm/bin
cp target/release/webhook-relay charm/bin/
cp target/release/relayd charm/bin/

# Pack the charm
cd charm
charmcraft pack
```

### Running tests

```bash
cd charm
python -m pytest tests/
```

## CI/CD

This charm includes GitHub Actions workflows for:
- **Testing**: Runs linting, unit tests, and builds binaries
- **Publishing**: Automatically publishes to Charmhub on tag pushes

### Setting up Charmhub publishing

1. Generate Charmhub credentials:
   ```bash
   charmcraft login --export charmcraft-auth.txt
   ```

2. Add the credentials as a GitHub secret named `CHARMCRAFT_AUTH`

3. Push a tag to trigger publishing:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

## License

MIT License - Copyright (c) 2026 Shih-Yuan Lee (FourDollars)
