#!/usr/bin/env python3
# Copyright 2026 Shih-Yuan Lee (FourDollars)
# See LICENSE file for licensing details.

"""Unit tests for webhook-relay charm."""

import unittest
from unittest.mock import MagicMock, Mock, patch, call
from pathlib import Path

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
        mock_path.return_value = mock_bin

        self.harness.charm.on.install.emit()

        self.assertFalse(self.harness.charm._stored.installed)

    @patch("charm.subprocess.run")
    def test_config_changed_webhook_mode(self, mock_run):
        """Test configuration change to server mode."""
        self.harness.charm._stored.installed = True

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

    @patch("charm.subprocess.run")
    def test_config_changed_relayd_mode(self, mock_run):
        """Test configuration change to client mode."""
        self.harness.charm._stored.installed = True

        # Set configuration for client mode
        self.harness.update_config(
            {
                "mode": "client",
                "url": "http://example.com/channel",
                "secret": "shared-secret",
                "key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            }
        )

        # Verify mode was stored
        self.assertEqual(self.harness.charm._stored.mode, "client")

    @patch("charm.subprocess.run")
    def test_config_changed_relayd_missing_url(self, mock_run):
        """Test client mode fails without URL."""
        self.harness.charm._stored.installed = True

        # Set configuration for client mode without URL
        self.harness.update_config({"mode": "client", "secret": "shared-secret"})

        # Should be in BlockedStatus due to missing URL
        self.assertIsInstance(self.harness.charm.unit.status, tuple)

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
            }
        )

        service_content = self.harness.charm._generate_relayd_service()

        # Verify service content contains expected values
        self.assertIn("http://example.com/channel", service_content)
        self.assertIn("ExecStart=", service_content)
        self.assertIn("/relayd", service_content)

    @patch("charm.Path.mkdir")
    def test_ensure_directories(self, mock_mkdir):
        """Test directory creation."""
        self.harness.charm._ensure_directories()

        # Verify mkdir was called
        self.assertTrue(mock_mkdir.called)


if __name__ == "__main__":
    unittest.main()
