#!/usr/bin/env python3
# Copyright 2026 Shih-Yuan Lee (FourDollars)
# See LICENSE file for licensing details.

"""Charm for webhook-relay service.

This charm deploys the webhook-relay service in two operational modes:
- webhook: SSE relay server accepting webhooks and broadcasting via SSE
- relayd: Relay client connecting to webhook server and decrypting messages
"""

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus

logger = logging.getLogger(__name__)


class WebhookRelayCharm(CharmBase):
    """Charm for the webhook-relay service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self._stored.set_default(mode=None, installed=False)

        # Register event handlers
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.remove, self._on_remove)

    def _on_install(self, event):
        """Handle the install event."""
        self.unit.status = MaintenanceStatus("Installing webhook-relay")

        # Check if binaries are available
        webhook_relay_bin = Path(self.charm_dir) / "bin" / "webhook-relay"
        relayd_bin = Path(self.charm_dir) / "bin" / "relayd"

        if not webhook_relay_bin.exists() or not relayd_bin.exists():
            self.unit.status = BlockedStatus("Binaries not found in charm")
            logger.error("Required binaries not found in charm directory")
            return

        # Create necessary directories
        self._ensure_directories()

        self._stored.installed = True
        logger.info("webhook-relay installed successfully")

    def _on_config_changed(self, event):
        """Handle configuration changes."""
        if not self._stored.installed:
            event.defer()
            return

        self.unit.status = MaintenanceStatus("Configuring webhook-relay")

        mode = self.config["mode"]

        # Validate mode
        if mode not in ["webhook", "relayd"]:
            self.unit.status = BlockedStatus(
                f"Invalid mode: {mode}. Must be 'webhook' or 'relayd'"
            )
            return

        # Mode-specific configuration and validation
        if mode == "webhook":
            if not self._configure_webhook_mode():
                return
        elif mode == "relayd":
            if not self._configure_relayd_mode():
                return

        # Store the current mode
        self._stored.mode = mode

        # Restart the service if it's running
        if self.unit.is_leader():
            self._restart_service()

        self.unit.status = ActiveStatus(f"Ready in {mode} mode")

    def _on_start(self, event):
        """Handle the start event."""
        if not self._stored.installed:
            event.defer()
            return

        if not self._stored.mode:
            self.unit.status = BlockedStatus("Service not configured")
            return

        self.unit.status = MaintenanceStatus("Starting webhook-relay")

        if self._start_service():
            self.unit.status = ActiveStatus(f"Running in {self._stored.mode} mode")
        else:
            self.unit.status = BlockedStatus("Failed to start service")

    def _on_stop(self, event):
        """Handle the stop event."""
        self.unit.status = MaintenanceStatus("Stopping webhook-relay")
        self._stop_service()

    def _on_remove(self, event):
        """Handle the remove event."""
        self.unit.status = MaintenanceStatus("Removing webhook-relay")
        self._stop_service()
        self._cleanup()

    def _ensure_directories(self):
        """Ensure required directories exist."""
        dirs = [
            Path("/var/lib/webhook-relay"),
            Path("/var/lib/webhook-relay/secret"),
            Path("/var/lib/webhook-relay/pem"),
            Path("/var/log/webhook-relay"),
        ]
        for directory in dirs:
            directory.mkdir(parents=True, exist_ok=True, mode=0o755)

    def _validate_channel_id(self, channel_id: str) -> bool:
        """Validate that channelId is a 40-character hexadecimal string (SHA1 format).

        Args:
            channel_id: The channel ID to validate

        Returns:
            True if valid, False otherwise
        """
        if not channel_id:
            return True  # Empty is valid (optional)

        # Must be exactly 40 characters and only contain hex digits (0-9, a-f, A-F)
        if len(channel_id) != 40:
            return False

        if not re.match(r"^[0-9a-fA-F]{40}$", channel_id):
            return False

        return True

    def _configure_webhook_mode(self) -> bool:
        """Configure webhook server mode."""
        logger.info("Configuring webhook mode")

        # Validate all configured channelIds first
        for i in range(10):
            channel_id = self.config.get(f"channelId{i}", "")
            if channel_id and not self._validate_channel_id(channel_id):
                self.unit.status = BlockedStatus(
                    f"Invalid channelId{i}: must be 40-character hexadecimal (SHA1 format). "
                    f"Generate with: uuidgen | sha1sum | awk '{{print $1}}'"
                )
                logger.error(f"Invalid channelId{i}: {channel_id}")
                return False

        # Write secret files (secret0-9) using channelId as filename
        for i in range(10):
            channel_id = self.config.get(f"channelId{i}", "")
            secret_value = self.config.get(f"secret{i}", "")

            # If channelId is configured, use it as the filename
            if channel_id and secret_value:
                secret_file = Path("/var/lib/webhook-relay/secret") / channel_id
                secret_file.write_text(secret_value)
                secret_file.chmod(0o600)
                logger.info(
                    f"Wrote secret file for channel {i} (channelId: {channel_id})"
                )
            elif secret_value:
                # Fallback to numeric filename if no channelId specified
                secret_file = Path("/var/lib/webhook-relay/secret") / str(i)
                secret_file.write_text(secret_value)
                secret_file.chmod(0o600)
                logger.info(
                    f"Wrote secret file for channel {i} (no channelId, using numeric)"
                )

        # Write public key files (key0-9) using channelId as filename
        for i in range(10):
            channel_id = self.config.get(f"channelId{i}", "")
            key_value = self.config.get(f"key{i}", "")

            # If channelId is configured, use it as the filename
            if channel_id and key_value:
                key_file = Path("/var/lib/webhook-relay/pem") / channel_id
                key_file.write_text(key_value)
                key_file.chmod(0o644)
                logger.info(
                    f"Wrote public key file for channel {i} (channelId: {channel_id})"
                )
            elif key_value:
                # Fallback to numeric filename if no channelId specified
                key_file = Path("/var/lib/webhook-relay/pem") / str(i)
                key_file.write_text(key_value)
                key_file.chmod(0o644)
                logger.info(
                    f"Wrote public key file for channel {i} (no channelId, using numeric)"
                )

        # Create systemd service file for webhook mode
        service_content = self._generate_webhook_service()
        service_file = Path("/etc/systemd/system/webhook-relay.service")
        service_file.write_text(service_content)

        # Reload systemd daemon
        subprocess.run(["systemctl", "daemon-reload"], check=True)

        return True

    def _configure_relayd_mode(self) -> bool:
        """Configure relay daemon (client) mode."""
        logger.info("Configuring relayd mode")

        # Validate required configuration
        url = self.config.get("url", "")
        if not url:
            self.unit.status = BlockedStatus("relayd mode requires 'url' configuration")
            return False

        # Write private key if provided
        key_value = self.config.get("key", "")
        if key_value:
            key_file = Path("/var/lib/webhook-relay/private_key.pem")
            key_file.write_text(key_value)
            key_file.chmod(0o600)
            logger.info("Wrote private key file")

        # Create systemd service file for relayd mode
        service_content = self._generate_relayd_service()
        service_file = Path("/etc/systemd/system/webhook-relay.service")
        service_file.write_text(service_content)

        # Reload systemd daemon
        subprocess.run(["systemctl", "daemon-reload"], check=True)

        return True

    def _generate_webhook_service(self) -> str:
        """Generate systemd service file for webhook mode."""
        webhook_bin = Path(self.charm_dir) / "bin" / "webhook-relay"

        # Build environment variables
        env_vars = [
            f"HOST={self.config['host']}",
            f"PORT={self.config['port']}",
            f"AUTH_USER={self.config['auth-user']}",
            f"AUTH_PASS={self.config['auth-pass']}",
            f"APP_PUBLIC_PATH={self.config['public-path']}",
            f"APP_BASE_PATH={self.config['base-path']}",
            f"PING_INTERVAL_MS={self.config['ping-interval-ms']}",
            "RUST_LOG=info",
        ]

        return f"""[Unit]
Description=Webhook Relay Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/webhook-relay
Environment={" ".join([f'"{e}"' for e in env_vars])}
ExecStart={webhook_bin}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

    def _generate_relayd_service(self) -> str:
        """Generate systemd service file for relayd mode."""
        relayd_bin = Path(self.charm_dir) / "bin" / "relayd"
        url = self.config["url"]

        # Build command arguments
        cmd_args = [str(relayd_bin), url]

        # Add private key if configured
        if self.config.get("key"):
            cmd_args.append("/var/lib/webhook-relay/private_key.pem")

        return f"""[Unit]
Description=Webhook Relay Client (relayd)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/webhook-relay
Environment="RUST_LOG=info"
ExecStart={" ".join(cmd_args)}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

    def _start_service(self) -> bool:
        """Start the webhook-relay service."""
        try:
            subprocess.run(["systemctl", "enable", "webhook-relay"], check=True)
            subprocess.run(["systemctl", "start", "webhook-relay"], check=True)
            logger.info("webhook-relay service started successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start service: {e}")
            return False

    def _stop_service(self):
        """Stop the webhook-relay service."""
        try:
            subprocess.run(["systemctl", "stop", "webhook-relay"], check=False)
            subprocess.run(["systemctl", "disable", "webhook-relay"], check=False)
            logger.info("webhook-relay service stopped")
        except Exception as e:
            logger.error(f"Error stopping service: {e}")

    def _restart_service(self):
        """Restart the webhook-relay service."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "webhook-relay"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:  # Service is running
                subprocess.run(["systemctl", "restart", "webhook-relay"], check=True)
                logger.info("webhook-relay service restarted")
        except Exception as e:
            logger.error(f"Error restarting service: {e}")

    def _cleanup(self):
        """Clean up resources."""
        service_file = Path("/etc/systemd/system/webhook-relay.service")
        if service_file.exists():
            service_file.unlink()
            subprocess.run(["systemctl", "daemon-reload"], check=False)

        logger.info("Cleanup completed")


if __name__ == "__main__":
    main(WebhookRelayCharm)
