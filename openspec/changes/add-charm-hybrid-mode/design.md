## Context
`charm/src/charm.py` writes one `/etc/systemd/system/webhook-relay.service` for either mode, and `_stored.mode`, `_start_service`, `_stop_service`, `_restart_service` and `_cleanup` assume a single service. The server options (`host`, `port`, `secret0..9`, `key0..9`, `auth-user`, ...) and client options (`url`, `forward`, `key`, `auth`, `store`) are already distinct names, so no option renames are needed.

## Goals / Non-Goals
- Goals: run server and client concurrently on one unit; keep `server` and `client` behavior unchanged for users; keep `juju expose` working on the configured port.
- Non-Goals: new config options, per-component status reporting, Juju relations between the two components.

## Decisions
- Decision: one systemd service per component. A shared unit cannot run two binaries independently, and separate units give independent restart and logs.
- Decision: derive enabled components from `mode` (`server` -> {server}, `client` -> {client}, `hybrid` -> {server, client}) and drive configure/start/stop/restart/cleanup from that set.
- Decision: all-or-nothing validation. If any enabled component fails validation the unit is blocked and no service is (re)started, so a half-configured hybrid never runs.
- Decision: reject a client `url` whose host and port match the local server (`host`/`port`, including loopback and `0.0.0.0` binds) to prevent an event loop. This is a best-effort check, not a guarantee against loops through other hosts.
- Decision: remove the legacy `webhook-relay.service` (stop, disable, delete, daemon-reload) when writing the new units. Switching modes also stops and removes the units of components that are no longer enabled.
- Decision: observe `upgrade-charm` and run the same migration and reconfiguration path as `config-changed`, so existing units migrate on charm refresh without a config change.
- Decision: restart services on all units. The current leader-only restart is wrong for per-unit services; hybrid exposes it because both halves must pick up config changes.
- Alternatives considered: one process supervising both (needs binary changes); a separate subordinate/second charm (more operational overhead, does not meet "same unit").

## Risks / Trade-offs
- Unit rename breaks external references -> documented as breaking, auto-migrated by the charm.
- Self-loop check can be bypassed via DNS or proxies -> documented as best-effort.
- Both components share data directories -> keep their paths distinct (client `store` must not overlap server paths).

## Migration Plan
1. On `upgrade-charm` and `config-changed`, if `webhook-relay.service` exists, stop, disable and delete it, then `systemctl daemon-reload`.
2. Write the per-component units and start only the enabled ones.
3. Rollback: redeploy the previous charm revision; it recreates `webhook-relay.service` on config-changed.

## Open Questions
- None.
