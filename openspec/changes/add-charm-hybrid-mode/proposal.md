## Why
The charm runs either the SSE relay server (`mode=server`) or the relay client (`mode=client`) on a unit, never both. Deployments that receive webhooks and also pull from an upstream relay (relay chaining, fan-out) need two applications. A `hybrid` mode lets one unit run both.

## What Changes
- Add `hybrid` as a valid value of the `mode` config option; it runs the server and the client on the same unit at the same time.
- Run each component as its own systemd service (`webhook-relay-server.service`, `webhook-relay-client.service`) instead of the single shared `webhook-relay.service`.
- Validate both the server option set and the client option set in hybrid mode; the unit goes blocked and starts neither service if either is invalid.
- Open the server port only when the server component is enabled (`server` or `hybrid`).
- Reject a hybrid configuration whose client `url` points at the unit's own server.
- Migrate existing units: remove the legacy `webhook-relay.service` when the new per-component services are written.
- Restart services on every unit, not only on the leader.
- **BREAKING**: the systemd unit name changes from `webhook-relay.service` to `webhook-relay-server.service` / `webhook-relay-client.service` for existing `server` and `client` deployments. The charm migrates automatically; anything external that references the old unit name must be updated.

## Impact
- Affected specs: `charm-deployment` (new capability)
- Affected code: `charm/src/charm.py`, `charm/charmcraft.yaml`, `charm/README.md`, `charm/tests/test_charm.py`
