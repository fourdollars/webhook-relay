## Why
The current webhook relay client silently ignores ping events but lacks a robust heartbeat mechanism to detect server disconnection. If the SSE connection is lost or the server becomes unresponsive, the client continues running indefinitely without realizing it's no longer receiving events. This creates a silent failure mode where webhooks may be missed without any indication.

## What Changes
- Add heartbeat timeout detection to the client when ping events are not received within expected intervals
- Implement automatic reconnection logic with exponential backoff
- Add failure threshold to exit with error code when reconnection attempts are exhausted
- Add comprehensive test coverage for heartbeat failure and reconnection scenarios
- **BREAKING**: Client will now exit with non-zero code on persistent connection failures

## Impact
- Affected specs: client-reliability (new capability)
- Affected code: client/src/main.rs (SSE event handling and connection management)
- Tests: New integration test for heartbeat failure scenarios
- Deployment: Client behavior becomes more robust but may exit when previously it would hang