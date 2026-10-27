## 1. Implementation
- [x] 1.1 Allow `hybrid` in the `mode` option and update its description in `charm/charmcraft.yaml`
- [x] 1.2 Split systemd handling into per-component services (`webhook-relay-server`, `webhook-relay-client`)
- [x] 1.3 Derive the enabled component set from `mode` and drive configure/start/stop/restart/cleanup from it
- [x] 1.4 Validate all enabled components before starting anything (all-or-nothing, blocked status on failure)
- [x] 1.5 Open the server port only for `server` and `hybrid`; close ports otherwise
- [x] 1.6 Reject a client `url` that targets the unit's own server
- [x] 1.7 Migrate and remove the legacy `webhook-relay.service`; remove units of disabled components on mode change
- [x] 1.8 Observe `upgrade-charm` and run migration and reconfiguration through the config-changed path
- [x] 1.9 Restart services on all units, not only the leader

## 2. Tests
- [x] 2.1 Hybrid config-changed writes both units and opens the server port
- [x] 2.2 Invalid server or client half blocks the unit and starts no service
- [x] 2.3 Self-referencing client `url` is rejected
- [x] 2.4 Legacy unit migration and mode switching remove stale units
- [x] 2.5 `upgrade-charm` migrates a legacy unit without a config change

## 3. Documentation
- [x] 3.1 Document hybrid mode, unit names and the breaking rename in `charm/README.md`
