## 1. Implementation
- [ ] 1.1 Add heartbeat timeout configuration with default values
- [ ] 1.2 Implement ping event timestamp tracking in SSE client
- [ ] 1.3 Add background task to monitor heartbeat timeout
- [ ] 1.4 Implement reconnection logic with exponential backoff
- [ ] 1.5 Add failure counter and exit logic after max attempts
- [ ] 1.6 Add logging for connection state changes

## 2. Testing
- [ ] 2.1 Create unit tests for heartbeat timeout detection
- [ ] 2.2 Create integration test for server stop scenario
- [ ] 2.3 Create integration test for temporary server unavailability
- [ ] 2.4 Create integration test for maximum reconnection attempts
- [ ] 2.5 Verify existing ping event handling still works

## 3. Documentation
- [ ] 3.1 Update client command line help with heartbeat options
- [ ] 3.2 Document new exit codes and their meanings
- [ ] 3.3 Update README with reliability behavior