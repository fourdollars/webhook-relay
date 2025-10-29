## Context
The webhook relay client currently handles SSE events but lacks resilience against connection failures. The server sends ping events every 7.5 seconds, but the client only ignores them without using them for connection health monitoring. This creates a reliability gap where silent failures can occur.

## Goals / Non-Goals
- **Goals:**
  - Detect server disconnection within reasonable timeframe (30-60 seconds)
  - Automatically recover from temporary network or server issues
  - Provide clear exit codes for monitoring and alerting
  - Maintain backward compatibility with server ping behavior

- **Non-Goals:**
  - Modify server ping frequency or format
  - Add configuration file support (use command line args/env vars)
  - Implement complex circuit breaker patterns

## Decisions
- **Heartbeat timeout**: 30 seconds (4x server ping interval of 7.5s)
- **Reconnection strategy**: Exponential backoff starting at 1s, max 30s
- **Max reconnection attempts**: 5 attempts before giving up
- **Exit codes**: 0 (success), 1 (connection failure), 2 (configuration error)
- **Implementation**: Use tokio::time::interval for timeout monitoring

### Alternatives considered
- **Fixed retry interval**: Rejected due to potential thundering herd if many clients restart simultaneously
- **Infinite retries**: Rejected as it prevents proper error detection in monitoring systems
- **Shorter timeout**: Rejected as network hiccups could cause false positives

## Risks / Trade-offs
- **Risk**: More aggressive connection management may cause unnecessary reconnections
  - **Mitigation**: Conservative 30s timeout and exponential backoff
- **Risk**: Client exit behavior change may break existing deployments
  - **Mitigation**: Clear documentation and exit code standardization

## Migration Plan
1. Deploy new client version with heartbeat feature
2. Monitor client logs for reconnection events
3. Adjust timeout values if needed based on production behavior
4. Update monitoring systems to alert on client exit codes

## Testing Support

### Server-Side Testing Environment Variables
To enable comprehensive testing of heartbeat timeout and reconnection logic, the server supports optional testing configuration:

- **`PING_STOP_AFTER_SECONDS`**: Stop sending ping events after specified seconds (for testing heartbeat timeout detection)
- **`SERVER_SHUTDOWN_AFTER_SECONDS`**: Shut down server completely after specified seconds (prevents infinite test loops)

### Test Configuration Example
```bash
# Start test server that stops pings at 10s and shuts down at 50s
PING_STOP_AFTER_SECONDS=10 SERVER_SHUTDOWN_AFTER_SECONDS=50 cargo run --package webhook-relay

# Run heartbeat integration test
cargo test test_client_detects_heartbeat_timeout --test heartbeat_integration
```

### Test Validation
The integration test (`test_client_detects_heartbeat_timeout`) verifies:
1. Server stops sending pings after configured duration (10s)
2. Client detects heartbeat timeout after threshold (30s default)
3. Client attempts reconnection with exponential backoff
4. Server shutdown prevents infinite reconnection loops
5. Client exits with correct error code (1) after max attempts exceeded

**Test Duration**: ~64 seconds (completes successfully without hanging)

### Implementation Notes
- Testing features are disabled by default (no production impact)
- Server logs clearly indicate when test configuration is active
- Both variables can be used independently or together
- Shutdown uses graceful exit (exit code 0) as it's a test helper, not a failure

## Open Questions
- Should heartbeat timeout be configurable via environment variable?
- Should we add metrics/health endpoint for client status?