# webhook-relay

A SSE webhook relay server made by Rust with additional secure supports for signature checking and encrypted payload.

```mermaid
sequenceDiagram
    participant WebhookSender
    participant HttpServer
    participant ChannelManager
    participant SSEClient
    activate HttpServer

    SSEClient->>HttpServer: GET /{id} (SSE Subscription)
    activate SSEClient
    HttpServer->>ChannelManager: Get or Create Channel (id)
    activate ChannelManager
    ChannelManager-->>ChannelManager: Check if 'id' exists
    alt Channel Exists
        ChannelManager-->>HttpServer: Existing channel for 'id'
    else Channel Does Not Exist
        ChannelManager-->>ChannelManager: Create new broadcast channel (id)
        ChannelManager-->>HttpServer: New channel for 'id'
    end
    deactivate ChannelManager
    HttpServer-->>SSEClient: Establish SSE Connection (BodyStream)
    
    Note over HttpServer, SSEClient: SSE connection established

    activate ChannelManager
    loop Every few seconds        
        ChannelManager->>ChannelManager: Check all active channels
        alt No Subscribers
            ChannelManager->>ChannelManager: Remove inactive channel
        else Has Subscribers
            ChannelManager->>ChannelManager: Send "ping" Payload to channel
            ChannelManager-->>SSEClient: event: ping<br>data: {subscriber_count}
        end
        deactivate ChannelManager
    end

    WebhookSender->>HttpServer: POST /{id} (Webhook Payload)
    activate WebhookSender
    HttpServer->>ChannelManager: Get Channel (id)
    activate ChannelManager
    alt Channel Exists
        ChannelManager-->>HttpServer: Channel for 'id'
        deactivate ChannelManager
    else Channel Does Not Exist
        HttpServer-->>WebhookSender: HTTP 404 Not Found
        Note over HttpServer, WebhookSender: Process terminates due to channel not found
    end

    HttpServer->>HttpServer: Read Request Body and Headers
    HttpServer->>HttpServer: Extract Signature Headers (X-Hub-Signature, etc.)
    HttpServer->>HttpServer: Get Secret Key for 'id'
    HttpServer->>HttpServer: Validate Signature using Secret Key
    alt Signature Valid
        HttpServer->>HttpServer: Create Payload Struct {body, headers}
        HttpServer->>ChannelManager: Send Payload to channel 'id'
        activate ChannelManager
        ChannelManager-->>SSEClient: Broadcast Payload to all subscribers
        alt Asymmetric Public Key Exist in DB
            ChannelManager-->>SSEClient: Encrypt Payload (Asymmetric & Symmetric)<br>Format as 'event: encrypted'
        else Asymmetric Public Key Do Not Exist in DB or Encryption Fails
            ChannelManager-->>SSEClient: Format as 'event: webhook' (Base64 encoded)
        end
        ChannelManager-->>WebhookSender: HTTP 200 OK
        deactivate ChannelManager
    else Signature Invalid
        HttpServer-->>WebhookSender: HTTP 401 Unauthorized
        deactivate WebhookSender
        Note over HttpServer, WebhookSender: Process terminates due to unauthorized
    end
    deactivate HttpServer
    deactivate SSEClient
```
## License

This project is licensed under the MIT License

MIT License

Copyright (c) 2025 Shih-Yuan Lee (FourDollars)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

...

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
