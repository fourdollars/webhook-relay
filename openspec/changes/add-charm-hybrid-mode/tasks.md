## 1. Implementation
- [ ] 1.1 Allow `hybrid` in the `mode` option and update its description in `charm/charmcraft.yaml`
- [ ] 1.2 Split systemd handling into per-component services (`webhook-relay-server`, `webhook-relay-client`)
- [ ] 1.3 Derive the enabled component set from `mode` and drive configure/start/stop/restart/cleanup from it
- [ ] 1.4 Validate all enabled components before starting anything (all-or-nothing, blocked status on failure)
- [ ] 1.5 Open the server port only for `server` and `hybrid`; close ports otherwise
- [ ] 1.6 Reject a client `url` that targets the unit's own server
- [ ] 1.7 Migrate and remove the legacy `webhook-relay.service`; remove units of disabled components on mode change
- [ ] 1.8 Observe `upgrade-charm` and run migration and reconfiguration through the config-changed path
- [ ] 1.9 Restart services on all units, not only the leader

## 2. Tests
- [ ] 2.1 Hybrid config-changed writes both units and opens the server port
- [ ] 2.2 Invalid server or client half blocks the unit and starts no service
- [ ] 2.3 Self-referencing client `url` is rejected
- [ ] 2.4 Legacy unit migration and mode switching remove stale units
- [ ] 2.5 `upgrade-charm` migrates a legacy unit without a config change

## 3. Documentation
- [ ] 3.1 Document hybrid mode, unit names and the breaking rename in `charm/README.md`
