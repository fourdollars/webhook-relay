## 1. Implementation
- [x] 1.1 Add heartbeat timeout configuration with default values
- [x] 1.2 Implement ping event timestamp tracking in SSE client
- [x] 1.3 Add background task to monitor heartbeat timeout
- [x] 1.4 Implement reconnection logic with exponential backoff
- [x] 1.5 Add failure counter and exit logic after max attempts
- [x] 1.6 Add logging for connection state changes

## 2. Testing
- [x] 2.1 Create unit tests for heartbeat timeout detection
- [x] 2.2 Create integration test for server stop scenario
- [x] 2.3 Create integration test for temporary server unavailability
- [x] 2.4 Create integration test for maximum reconnection attempts
- [x] 2.5 Verify existing ping event handling still works
- [x] 2.6 Add server-side testing environment variables (PING_STOP_AFTER_SECONDS, SERVER_SHUTDOWN_AFTER_SECONDS)
- [x] 2.7 Ensure tests complete without hanging (server auto-shutdown)

## 3. Documentation
- [x] 3.1 Update client command line help with heartbeat options
- [x] 3.2 Document new exit codes and their meanings
- [x] 3.3 Update README with reliability behavior