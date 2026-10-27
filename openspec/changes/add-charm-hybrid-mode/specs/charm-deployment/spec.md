## ADDED Requirements
### Requirement: Hybrid Operation Mode
The charm SHALL accept `hybrid` as a value of the `mode` option and, in that mode, SHALL run the relay server and the relay client concurrently on the same unit.

#### Scenario: Both components run
- **WHEN** `mode` is `hybrid` and both the server and client options are valid
- **THEN** the unit runs `webhook-relay-server.service` and `webhook-relay-client.service` and reports an active status

#### Scenario: Server mode unchanged
- **WHEN** `mode` is `server`
- **THEN** only `webhook-relay-server.service` runs

#### Scenario: Client mode unchanged
- **WHEN** `mode` is `client`
- **THEN** only `webhook-relay-client.service` runs

### Requirement: Per-Component Services
The charm SHALL run each component as its own systemd service and SHALL remove the legacy `webhook-relay.service` when migrating, on both `config-changed` and `upgrade-charm`.

#### Scenario: Legacy service migrated
- **WHEN** the charm configures a unit that has a legacy `webhook-relay.service`
- **THEN** the legacy service is stopped, disabled and removed before the new services are started

#### Scenario: Migration on charm upgrade
- **WHEN** the charm is upgraded on a unit that has a legacy `webhook-relay.service`
- **THEN** the unit migrates to the per-component services without requiring a configuration change

#### Scenario: Mode switch removes stale service
- **WHEN** `mode` changes from `hybrid` to `server`
- **THEN** `webhook-relay-client.service` is stopped, disabled and removed

### Requirement: All-Or-Nothing Hybrid Validation
In hybrid mode the charm SHALL validate the server and client options together and SHALL NOT start either service unless both are valid.

#### Scenario: Invalid client half
- **WHEN** `mode` is `hybrid` and the client `url` is empty
- **THEN** the unit status is blocked and neither service is started

### Requirement: Relay Loop Prevention
The charm SHALL reject a hybrid configuration whose client `url` targets the unit's own server.

#### Scenario: Client points at local server
- **WHEN** `mode` is `hybrid` and the client `url` host and port match the local `host` and `port`
- **THEN** the unit status is blocked with a message naming the loop

### Requirement: Server Port Exposure
The charm SHALL open the configured `port` only when the server component is enabled, so that `juju expose` takes effect for `server` and `hybrid` modes.

#### Scenario: Hybrid opens the port
- **WHEN** `mode` is `hybrid` and `port` is 3000
- **THEN** the unit has 3000/tcp opened

#### Scenario: Client mode opens nothing
- **WHEN** `mode` is `client`
- **THEN** the unit has no opened ports

### Requirement: Restart On Every Unit
The charm SHALL restart running component services on configuration changes on every unit, not only on the leader.

#### Scenario: Non-leader restarts
- **WHEN** configuration changes on a non-leader unit with a running service
- **THEN** that unit restarts its running component services
