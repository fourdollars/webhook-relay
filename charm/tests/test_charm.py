#!/usr/bin/env python3
# Copyright 2026 Shih-Yuan Lee (FourDollars)
# See LICENSE file for licensing details.

"""Unit tests for webhook-relay charm."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ops.testing import Harness

from charm import WebhookRelayCharm


class TestWebhookRelayCharm(unittest.TestCase):
    """Test cases for WebhookRelayCharm."""

    def setUp(self):
        """Set up test harness."""
        self.harness = Harness(WebhookRelayCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("charm.Path")
    def test_install_success(self, mock_path):
        """Test successful installation."""
        # Mock binary paths to exist
        mock_webhook_bin = MagicMock()
        mock_webhook_bin.exists.return_value = True
        mock_relayd_bin = MagicMock()
        mock_relayd_bin.exists.return_value = True

        mock_path.return_value = mock_webhook_bin

        with patch.object(self.harness.charm, "_ensure_directories"):
            self.harness.charm.on.install.emit()

        self.assertTrue(self.harness.charm._stored.installed)

    @patch("charm.Path")
    def test_install_missing_binaries(self, mock_path):
        """Test installation fails when binaries are missing."""
        # Mock binary paths to not exist
        mock_bin = MagicMock()
        mock_bin.exists.return_value = False

        # Mock Path() call and the / operations
        mock_charm_dir_path = MagicMock()
        mock_bin_dir = MagicMock()
        mock_bin_dir.__truediv__ = MagicMock(return_value=mock_bin)
        mock_charm_dir_path.__truediv__ = MagicMock(return_value=mock_bin_dir)
        mock_path.return_value = mock_charm_dir_path

        self.harness.charm.on.install.emit()

        # _stored.installed should not be set when binaries are missing
        self.assertFalse(
            hasattr(self.harness.charm._stored, "installed")
            and self.harness.charm._stored.installed
        )

    @patch("charm.Path")
    @patch("charm.subprocess.run")
    def test_config_changed_webhook_mode(self, mock_run, mock_path_class):
        """Test configuration change to server mode."""
        self.harness.charm._stored.installed = True

        # Mock Path for secret/key/auth file operations
        mock_path_obj = MagicMock()
        mock_path_obj.exists.return_value = False
        mock_path_class.return_value = mock_path_obj

        # Set configuration for server mode
        self.harness.update_config(
            {
                "mode": "server",
                "host": "0.0.0.0",
                "port": 3000,
                "secret0": "test-secret",
                "key0": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            }
        )

        # Verify mode was stored
        self.assertEqual(self.harness.charm._stored.mode, "server")
        self.assertEqual(
            {(p.protocol, p.port) for p in self.harness.charm.unit.opened_ports()},
            {("tcp", 3000)},
        )

        # Changing the port config replaces the opened port
        self.harness.update_config({"port": 4000})
        self.assertEqual(
            {(p.protocol, p.port) for p in self.harness.charm.unit.opened_ports()},
            {("tcp", 4000)},
        )

    @patch("charm.Path")
    @patch("charm.subprocess.run")
    def test_config_changed_relayd_mode(self, mock_run, mock_path_class):
        """Test configuration change to client mode."""
        self.harness.charm._stored.installed = True

        # Mock Path for key file operations and store dir creation
        mock_path_obj = MagicMock()
        mock_path_obj.is_absolute.return_value = True
        mock_path_class.return_value = mock_path_obj

        # Set configuration for client mode
        self.harness.update_config(
            {
                "mode": "client",
                "url": "http://example.com/channel",
                "key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
                "store": "/srv/payload_rw",
                "auth": "user:pass",
            }
        )

        # Verify mode was stored
        self.assertEqual(self.harness.charm._stored.mode, "client")
        self.assertEqual(self.harness.charm.unit.opened_ports(), set())

    @patch("charm.Path")
    def test_config_changed_relayd_invalid_store_path(self, mock_path_class):
        """Test client mode fails when store path is not absolute."""
        self.harness.charm._stored.installed = True

        mock_path_obj = MagicMock()
        mock_path_obj.is_absolute.return_value = False
        mock_path_class.return_value = mock_path_obj

        self.harness.update_config(
            {
                "mode": "client",
                "url": "http://example.com/channel",
                "store": "relative/path",
            }
        )

        from ops.model import BlockedStatus

        self.assertIsInstance(self.harness.charm.unit.status, BlockedStatus)

    @patch("charm.subprocess.run")
    def test_config_changed_relayd_missing_url(self, mock_run):
        """Test client mode fails without URL."""
        self.harness.charm._stored.installed = True

        # Set configuration for client mode without URL
        self.harness.update_config({"mode": "client"})

        # Should be in BlockedStatus due to missing URL
        from ops.model import BlockedStatus

        self.assertIsInstance(self.harness.charm.unit.status, BlockedStatus)

    def test_config_changed_invalid_mode(self):
        """Test configuration fails with invalid mode."""
        self.harness.charm._stored.installed = True

        self.harness.update_config({"mode": "invalid"})

        # Mode should not be stored
        self.assertIsNone(self.harness.charm._stored.mode)

    @patch("charm.subprocess.run")
    def test_start_service_webhook_mode(self, mock_run):
        """Test starting service in server mode."""
        self.harness.charm._stored.installed = True
        self.harness.charm._stored.mode = "server"

        self.harness.charm.on.start.emit()

        # Verify systemctl commands were called
        calls = mock_run.call_args_list
        self.assertTrue(any("enable" in str(c) for c in calls))
        self.assertTrue(any("start" in str(c) for c in calls))

    @patch("charm.subprocess.run")
    def test_stop_service(self, mock_run):
        """Test stopping service."""
        self.harness.charm._stored.installed = True
        self.harness.charm._stored.mode = "server"

        self.harness.charm.on.stop.emit()

        # Verify systemctl stop was called
        calls = mock_run.call_args_list
        self.assertTrue(any("stop" in str(c) for c in calls))

    def test_generate_webhook_service(self):
        """Test webhook service file generation."""
        self.harness.update_config(
            {
                "mode": "server",
                "host": "127.0.0.1",
                "port": 8000,
                "auth-user": "admin",
                "auth-pass": "secret",
                "public-path": "/public",
                "base-path": "/base",
                "ping-interval-ms": 5000,
            }
        )

        service_content = self.harness.charm._generate_webhook_service()

        # Verify service content contains expected values
        self.assertIn("HOST=127.0.0.1", service_content)
        self.assertIn("PORT=8000", service_content)
        self.assertIn("AUTH_USER=admin", service_content)
        self.assertIn("PING_INTERVAL_MS=5000", service_content)
        self.assertIn("ExecStart=", service_content)

    def test_generate_relayd_service(self):
        """Test relayd service file generation."""
        self.harness.update_config(
            {
                "mode": "client",
                "url": "http://example.com/channel",
                "key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
                "store": "/srv/payload_rw",
                "auth": "alice:secret",
            }
        )

        service_content = self.harness.charm._generate_relayd_service()

        # Verify service content contains expected values
        self.assertIn("http://example.com/channel", service_content)
        self.assertIn("ExecStart=", service_content)
        self.assertIn("/relayd", service_content)
        self.assertIn("--store /srv/payload_rw", service_content)
        self.assertIn("--user alice --pass secret", service_content)

    @patch("charm.Path")
    def test_config_changed_server_auth_without_channel_is_blocked(
        self, mock_path_class
    ):
        """Test server mode blocks authN when channelN is missing."""
        self.harness.charm._stored.installed = True

        mock_path_obj = MagicMock()
        mock_path_obj.exists.return_value = False
        mock_path_class.return_value = mock_path_obj

        self.harness.update_config(
            {
                "mode": "server",
                "auth0": "user:pass",
            }
        )

        from ops.model import BlockedStatus

        self.assertIsInstance(self.harness.charm.unit.status, BlockedStatus)

    @patch("charm.Path")
    def test_config_changed_client_invalid_auth_is_blocked(self, mock_path_class):
        """Test client mode blocks invalid auth format."""
        self.harness.charm._stored.installed = True

        mock_path_obj = MagicMock()
        mock_path_obj.is_absolute.return_value = True
        mock_path_class.return_value = mock_path_obj

        self.harness.update_config(
            {
                "mode": "client",
                "url": "http://example.com/channel",
                "auth": "invalid-format",
            }
        )

        from ops.model import BlockedStatus

        self.assertIsInstance(self.harness.charm.unit.status, BlockedStatus)

    @patch("charm.Path.mkdir")
    def test_ensure_directories(self, mock_mkdir):
        """Test directory creation."""
        self.harness.charm._ensure_directories()

        # Verify mkdir was called
        self.assertTrue(mock_mkdir.called)


class TestHybridMode(unittest.TestCase):
    """Test cases for hybrid mode and per-component services."""

    def setUp(self):
        self.harness = Harness(WebhookRelayCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.harness.charm._stored.installed = True

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.systemd = Path(tmp.name)
        for target in (
            patch("charm.SYSTEMD_DIR", str(self.systemd)),
            patch.object(
                WebhookRelayCharm, "_configure_webhook_mode", return_value=True
            ),
        ):
            target.start()
            self.addCleanup(target.stop)

        run = patch("charm.subprocess.run")
        self.mock_run = run.start()
        self.mock_run.return_value = MagicMock(returncode=0)
        self.addCleanup(run.stop)

    def _units(self):
        return sorted(p.name for p in self.systemd.iterdir())

    def _systemctl(self, verb):
        return [c.args[0] for c in self.mock_run.call_args_list if c.args[0][1] == verb]

    def test_hybrid_writes_both_units_and_opens_port(self):
        with patch.object(
            WebhookRelayCharm, "_configure_relayd_mode", return_value=True
        ):
            self.harness.update_config(
                {"mode": "hybrid", "url": "http://upstream:3000/c", "port": 3000}
            )

        self.assertEqual(
            self._units(),
            ["webhook-relay-client.service", "webhook-relay-server.service"],
        )
        self.assertEqual(
            {(p.protocol, p.port) for p in self.harness.charm.unit.opened_ports()},
            {("tcp", 3000)},
        )

    def test_hybrid_invalid_client_blocks_and_starts_nothing(self):
        from ops.model import BlockedStatus

        self.harness.charm._stored.started = True
        self.harness.update_config({"mode": "hybrid"})  # client url missing

        self.assertIsInstance(self.harness.charm.unit.status, BlockedStatus)
        self.assertEqual(self._units(), [])
        self.assertEqual(self._systemctl("restart"), [])

    def test_hybrid_rejects_client_pointing_at_local_server(self):
        from ops.model import BlockedStatus

        self.harness.update_config(
            {"mode": "hybrid", "url": "http://localhost:3000/c", "port": 3000}
        )

        self.assertIsInstance(self.harness.charm.unit.status, BlockedStatus)
        self.assertIn("loop", self.harness.charm.unit.status.message)
        self.assertEqual(self._units(), [])

    def test_mode_switch_removes_stale_unit_and_closes_port(self):
        with patch.object(
            WebhookRelayCharm, "_configure_relayd_mode", return_value=True
        ):
            self.harness.update_config(
                {"mode": "hybrid", "url": "http://upstream:3000/c"}
            )
            self.harness.update_config({"mode": "client"})

        self.assertEqual(self._units(), ["webhook-relay-client.service"])
        self.assertEqual(self.harness.charm.unit.opened_ports(), set())

    def test_upgrade_migrates_running_legacy_service(self):
        (self.systemd / "webhook-relay.service").write_text("legacy")

        self.harness.charm.on.upgrade_charm.emit()

        self.assertEqual(self._units(), ["webhook-relay-server.service"])
        self.assertTrue(self.harness.charm._stored.started)
        self.assertIn(
            ["systemctl", "restart", "webhook-relay-server"], self._systemctl("restart")
        )
        self.assertNotIn("webhook-relay.service", self._units())


if __name__ == "__main__":
    unittest.main()
