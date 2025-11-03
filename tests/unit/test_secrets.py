"""Tests for Kubernetes secrets utilities."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest
from kubernetes import client

from wasabi_s3_operator.utils.secrets import (
    cleanup_expired_previous_secrets,
    create_previous_secret,
    create_secret,
    delete_secret,
    get_secret_value,
    list_previous_secrets,
    read_secret_data,
    update_secret,
)


class TestGetSecretValue:
    """Test cases for get_secret_value function."""

    def test_get_secret_value_success(self):
        """Test successfully getting a secret value."""
        mock_api = Mock()
        mock_secret = Mock()
        encoded_value = base64.b64encode(b"test-value").decode("utf-8")
        mock_secret.data = {"test-key": encoded_value}
        mock_api.read_namespaced_secret.return_value = mock_secret

        result = get_secret_value(mock_api, "default", "test-secret", "test-key")

        assert result == "test-value"
        mock_api.read_namespaced_secret.assert_called_once_with(
            name="test-secret", namespace="default"
        )

    def test_get_secret_value_bytes(self):
        """Test getting secret value that's already bytes."""
        mock_api = Mock()
        mock_secret = Mock()
        mock_secret.data = {"test-key": b"test-value"}
        mock_api.read_namespaced_secret.return_value = mock_secret

        result = get_secret_value(mock_api, "default", "test-secret", "test-key")

        assert result == "test-value"

    def test_get_secret_value_key_not_found(self):
        """Test error when key not found in secret."""
        mock_api = Mock()
        mock_secret = Mock()
        mock_secret.data = {"other-key": "value"}
        mock_api.read_namespaced_secret.return_value = mock_secret

        with pytest.raises(ValueError, match="Key 'test-key' not found"):
            get_secret_value(mock_api, "default", "test-secret", "test-key")

    def test_get_secret_value_secret_not_found(self):
        """Test error when secret not found."""
        mock_api = Mock()
        mock_api.read_namespaced_secret.side_effect = client.exceptions.ApiException(status=404)

        with pytest.raises(ValueError, match="Secret 'test-secret' not found"):
            get_secret_value(mock_api, "default", "test-secret", "test-key")

    def test_get_secret_value_api_error(self):
        """Test handling of other API errors."""
        mock_api = Mock()
        mock_api.read_namespaced_secret.side_effect = client.exceptions.ApiException(status=500)

        with pytest.raises(client.exceptions.ApiException):
            get_secret_value(mock_api, "default", "test-secret", "test-key")

    def test_get_secret_value_plain_string(self):
        """Test getting secret value that's already a plain string."""
        mock_api = Mock()
        mock_secret = Mock()
        # Simulate a string that can't be base64 decoded
        mock_secret.data = {"test-key": "plain-value!@#"}
        mock_api.read_namespaced_secret.return_value = mock_secret

        result = get_secret_value(mock_api, "default", "test-secret", "test-key")

        # Should return the string as-is when base64 decode fails
        assert result == "plain-value!@#"


class TestCreateSecret:
    """Test cases for create_secret function."""

    def test_create_secret_success(self):
        """Test successfully creating a secret."""
        mock_api = Mock()
        data = {"key1": "value1", "key2": "value2"}

        create_secret(mock_api, "default", "test-secret", data)

        mock_api.create_namespaced_secret.assert_called_once()
        call_args = mock_api.create_namespaced_secret.call_args
        assert call_args[1]["namespace"] == "default"
        
        secret = call_args[1]["body"]
        assert secret.metadata.name == "test-secret"
        assert secret.type == "Opaque"
        # Verify data is base64 encoded
        assert "key1" in secret.data
        assert secret.data["key1"] == base64.b64encode(b"value1").decode("utf-8")

    def test_create_secret_with_owner_references(self):
        """Test creating secret with owner references."""
        mock_api = Mock()
        data = {"key": "value"}
        owner_refs = [{"kind": "AccessKey", "name": "test-key"}]

        create_secret(mock_api, "default", "test-secret", data, owner_references=owner_refs)

        call_args = mock_api.create_namespaced_secret.call_args
        secret = call_args[1]["body"]
        assert secret.metadata.owner_references == owner_refs


class TestUpdateSecret:
    """Test cases for update_secret function."""

    def test_update_secret_success(self):
        """Test successfully updating a secret."""
        mock_api = Mock()
        data = {"key1": "updated-value"}

        update_secret(mock_api, "default", "test-secret", data)

        mock_api.patch_namespaced_secret.assert_called_once()
        call_args = mock_api.patch_namespaced_secret.call_args
        assert call_args[1]["name"] == "test-secret"
        assert call_args[1]["namespace"] == "default"
        
        secret = call_args[1]["body"]
        assert secret.metadata.name == "test-secret"
        # Verify data is base64 encoded
        assert secret.data["key1"] == base64.b64encode(b"updated-value").decode("utf-8")


class TestDeleteSecret:
    """Test cases for delete_secret function."""

    def test_delete_secret_success(self):
        """Test successfully deleting a secret."""
        mock_api = Mock()

        delete_secret(mock_api, "default", "test-secret")

        mock_api.delete_namespaced_secret.assert_called_once_with(
            name="test-secret", namespace="default"
        )


class TestReadSecretData:
    """Test cases for read_secret_data function."""

    def test_read_secret_data_success(self):
        """Test successfully reading all secret data."""
        mock_api = Mock()
        mock_secret = Mock()
        mock_secret.data = {
            "key1": base64.b64encode(b"value1").decode("utf-8"),
            "key2": base64.b64encode(b"value2").decode("utf-8"),
        }
        mock_api.read_namespaced_secret.return_value = mock_secret

        result = read_secret_data(mock_api, "default", "test-secret")

        assert result == {"key1": "value1", "key2": "value2"}

    def test_read_secret_data_bytes_values(self):
        """Test reading secret data with bytes values."""
        mock_api = Mock()
        mock_secret = Mock()
        mock_secret.data = {"key1": b"value1", "key2": b"value2"}
        mock_api.read_namespaced_secret.return_value = mock_secret

        result = read_secret_data(mock_api, "default", "test-secret")

        assert result == {"key1": "value1", "key2": "value2"}

    def test_read_secret_data_empty(self):
        """Test reading empty secret data."""
        mock_api = Mock()
        mock_secret = Mock()
        mock_secret.data = None
        mock_api.read_namespaced_secret.return_value = mock_secret

        result = read_secret_data(mock_api, "default", "test-secret")

        assert result == {}

    def test_read_secret_data_not_found(self):
        """Test error when secret not found."""
        mock_api = Mock()
        mock_api.read_namespaced_secret.side_effect = client.exceptions.ApiException(status=404)

        with pytest.raises(ValueError, match="Secret 'test-secret' not found"):
            read_secret_data(mock_api, "default", "test-secret")


class TestCreatePreviousSecret:
    """Test cases for create_previous_secret function."""

    def test_create_previous_secret_success(self):
        """Test successfully creating a previous secret."""
        mock_api = Mock()

        create_previous_secret(
            mock_api,
            "default",
            "test-secret-previous-123",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "2024-01-01T00:00:00Z",
            "test-access-key",
        )

        mock_api.create_namespaced_secret.assert_called_once()
        call_args = mock_api.create_namespaced_secret.call_args
        secret = call_args[1]["body"]
        
        assert secret.metadata.name == "test-secret-previous-123"
        assert secret.metadata.labels["s3.cloud37.dev/previous-secret"] == "true"
        assert secret.metadata.labels["s3.cloud37.dev/access-key-name"] == "test-access-key"
        assert secret.metadata.labels["s3.cloud37.dev/rotated-at"] == "2024-01-01T00:00:00Z"
        assert secret.string_data["access-key-id"] == "AKIAIOSFODNN7EXAMPLE"

    def test_create_previous_secret_with_owner_refs(self):
        """Test creating previous secret with owner references."""
        mock_api = Mock()
        owner_refs = [{"kind": "AccessKey", "name": "test-key"}]

        create_previous_secret(
            mock_api,
            "default",
            "test-secret-previous-123",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "2024-01-01T00:00:00Z",
            "test-access-key",
            owner_references=owner_refs,
        )

        call_args = mock_api.create_namespaced_secret.call_args
        secret = call_args[1]["body"]
        assert secret.metadata.owner_references == owner_refs


class TestListPreviousSecrets:
    """Test cases for list_previous_secrets function."""

    def test_list_previous_secrets_success(self):
        """Test successfully listing previous secrets."""
        mock_api = Mock()
        mock_secret1 = Mock()
        mock_secret1.metadata.name = "secret-1"
        mock_secret1.metadata.labels = {
            "s3.cloud37.dev/previous-secret": "true",
            "s3.cloud37.dev/access-key-name": "test-key",
            "s3.cloud37.dev/rotated-at": "2024-01-01T00:00:00Z",
        }
        
        mock_secrets_list = Mock()
        mock_secrets_list.items = [mock_secret1]
        mock_api.list_namespaced_secret.return_value = mock_secrets_list

        result = list_previous_secrets(mock_api, "default", "test-key")

        assert len(result) == 1
        assert result[0]["name"] == "secret-1"
        assert result[0]["rotated_at"] == "2024-01-01T00:00:00Z"
        assert result[0]["is_expired"] is False

    def test_list_previous_secrets_with_retention(self):
        """Test listing previous secrets with retention filtering."""
        mock_api = Mock()
        
        # Create a recent secret and an old secret
        now = datetime.now(timezone.utc)
        old_date = (now - timedelta(days=40)).isoformat()
        recent_date = (now - timedelta(days=5)).isoformat()
        
        mock_old_secret = Mock()
        mock_old_secret.metadata.name = "old-secret"
        mock_old_secret.metadata.labels = {
            "s3.cloud37.dev/rotated-at": old_date,
        }
        
        mock_recent_secret = Mock()
        mock_recent_secret.metadata.name = "recent-secret"
        mock_recent_secret.metadata.labels = {
            "s3.cloud37.dev/rotated-at": recent_date,
        }
        
        mock_secrets_list = Mock()
        mock_secrets_list.items = [mock_old_secret, mock_recent_secret]
        mock_api.list_namespaced_secret.return_value = mock_secrets_list

        result = list_previous_secrets(
            mock_api, "default", "test-key", include_expired=False, retention_days=30
        )

        # Only recent secret should be returned (old one is expired)
        assert len(result) == 1
        assert result[0]["name"] == "recent-secret"

    def test_list_previous_secrets_include_expired(self):
        """Test listing previous secrets including expired ones."""
        mock_api = Mock()
        
        now = datetime.now(timezone.utc)
        old_date = (now - timedelta(days=40)).isoformat()
        
        mock_old_secret = Mock()
        mock_old_secret.metadata.name = "old-secret"
        mock_old_secret.metadata.labels = {
            "s3.cloud37.dev/rotated-at": old_date,
        }
        
        mock_secrets_list = Mock()
        mock_secrets_list.items = [mock_old_secret]
        mock_api.list_namespaced_secret.return_value = mock_secrets_list

        result = list_previous_secrets(
            mock_api, "default", "test-key", include_expired=True, retention_days=30
        )

        # Expired secret should be included
        assert len(result) == 1
        assert result[0]["is_expired"] is True

    def test_list_previous_secrets_error(self):
        """Test handling errors when listing secrets."""
        mock_api = Mock()
        mock_api.list_namespaced_secret.side_effect = Exception("API error")

        result = list_previous_secrets(mock_api, "default", "test-key")

        # Should return empty list on error
        assert result == []

    def test_list_previous_secrets_no_rotated_at_label(self):
        """Test handling secrets without rotated_at label."""
        mock_api = Mock()
        
        mock_secret = Mock()
        mock_secret.metadata.name = "secret-1"
        mock_secret.metadata.labels = {
            "s3.cloud37.dev/previous-secret": "true",
            # Missing rotated-at label
        }
        
        mock_secrets_list = Mock()
        mock_secrets_list.items = [mock_secret]
        mock_api.list_namespaced_secret.return_value = mock_secrets_list

        result = list_previous_secrets(mock_api, "default", "test-key")

        # Secret without rotated_at should be skipped
        assert len(result) == 0


class TestCleanupExpiredPreviousSecrets:
    """Test cases for cleanup_expired_previous_secrets function."""

    @patch("wasabi_s3_operator.utils.secrets.list_previous_secrets")
    @patch("wasabi_s3_operator.utils.secrets.delete_secret")
    def test_cleanup_expired_secrets(self, mock_delete, mock_list):
        """Test cleaning up expired secrets."""
        mock_api = Mock()
        mock_list.return_value = [
            {"name": "expired-1", "is_expired": True},
            {"name": "expired-2", "is_expired": True},
            {"name": "not-expired", "is_expired": False},
        ]

        result = cleanup_expired_previous_secrets(mock_api, "default", "test-key", 30)

        # Should only delete expired secrets
        assert len(result) == 2
        assert "expired-1" in result
        assert "expired-2" in result
        assert mock_delete.call_count == 2

    @patch("wasabi_s3_operator.utils.secrets.list_previous_secrets")
    @patch("wasabi_s3_operator.utils.secrets.delete_secret")
    def test_cleanup_expired_secrets_delete_error(self, mock_delete, mock_list):
        """Test cleanup continues even if deletion fails."""
        mock_api = Mock()
        mock_list.return_value = [
            {"name": "expired-1", "is_expired": True},
            {"name": "expired-2", "is_expired": True},
        ]
        
        # First delete succeeds, second fails
        mock_delete.side_effect = [None, Exception("Delete failed")]

        result = cleanup_expired_previous_secrets(mock_api, "default", "test-key", 30)

        # Should return only successfully deleted secret
        assert len(result) == 1
        assert "expired-1" in result

    @patch("wasabi_s3_operator.utils.secrets.list_previous_secrets")
    def test_cleanup_no_expired_secrets(self, mock_list):
        """Test cleanup when there are no expired secrets."""
        mock_api = Mock()
        mock_list.return_value = []

        result = cleanup_expired_previous_secrets(mock_api, "default", "test-key", 30)

        assert len(result) == 0
