"""Tests for Kubernetes event utilities."""

from __future__ import annotations

from unittest.mock import patch

from wasabi_s3_operator.utils.events import (
    emit_access_key_created,
    emit_access_key_rotated,
    emit_bucket_created,
    emit_bucket_deleted,
    emit_bucket_updated,
    emit_event,
    emit_policy_applied,
    emit_policy_failed,
    emit_reconcile_failed,
    emit_reconcile_started,
    emit_validate_failed,
    emit_validate_succeeded,
)


class TestEmitEvent:
    """Test cases for emit_event function."""

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_event_normal(self, mock_event):
        """Test emitting normal event."""
        meta = {"name": "test-resource", "namespace": "default"}
        
        emit_event(meta, "TestReason", "Test message")
        
        mock_event.assert_called_once_with(
            meta,
            reason="TestReason",
            message="Test message",
            type="Normal",
        )

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_event_warning(self, mock_event):
        """Test emitting warning event."""
        meta = {"name": "test-resource", "namespace": "default"}
        
        emit_event(meta, "ErrorReason", "Error occurred", type_="Warning")
        
        mock_event.assert_called_once_with(
            meta,
            reason="ErrorReason",
            message="Error occurred",
            type="Warning",
        )


class TestReconcileEvents:
    """Test cases for reconciliation events."""

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_reconcile_started(self, mock_event):
        """Test emitting reconcile started event."""
        meta = {"name": "test-resource", "namespace": "default"}
        
        emit_reconcile_started(meta)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert "started" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_reconcile_failed(self, mock_event):
        """Test emitting reconcile failed event."""
        meta = {"name": "test-resource", "namespace": "default"}
        error_msg = "Failed to connect to S3"
        
        emit_reconcile_failed(meta, error_msg)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert error_msg in call_args[1]["message"]
        assert call_args[1]["type"] == "Warning"


class TestValidationEvents:
    """Test cases for validation events."""

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_validate_succeeded(self, mock_event):
        """Test emitting validation succeeded event."""
        meta = {"name": "test-resource", "namespace": "default"}
        
        emit_validate_succeeded(meta)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert "succeeded" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_validate_failed(self, mock_event):
        """Test emitting validation failed event."""
        meta = {"name": "test-resource", "namespace": "default"}
        error_msg = "Invalid bucket name format"
        
        emit_validate_failed(meta, error_msg)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert error_msg in call_args[1]["message"]
        assert call_args[1]["type"] == "Warning"


class TestBucketEvents:
    """Test cases for bucket-related events."""

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_bucket_created(self, mock_event):
        """Test emitting bucket created event."""
        meta = {"name": "my-bucket", "namespace": "default"}
        bucket_name = "my-s3-bucket"
        
        emit_bucket_created(meta, bucket_name)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert bucket_name in call_args[1]["message"]
        assert "created" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_bucket_updated(self, mock_event):
        """Test emitting bucket updated event."""
        meta = {"name": "my-bucket", "namespace": "default"}
        bucket_name = "my-s3-bucket"
        
        emit_bucket_updated(meta, bucket_name)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert bucket_name in call_args[1]["message"]
        assert "updated" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_bucket_deleted(self, mock_event):
        """Test emitting bucket deleted event."""
        meta = {"name": "my-bucket", "namespace": "default"}
        bucket_name = "my-s3-bucket"
        
        emit_bucket_deleted(meta, bucket_name)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert bucket_name in call_args[1]["message"]
        assert "deleted" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"


class TestPolicyEvents:
    """Test cases for policy-related events."""

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_policy_applied(self, mock_event):
        """Test emitting policy applied event."""
        meta = {"name": "my-policy", "namespace": "default"}
        bucket_name = "my-s3-bucket"
        
        emit_policy_applied(meta, bucket_name)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert bucket_name in call_args[1]["message"]
        assert "applied" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_policy_failed(self, mock_event):
        """Test emitting policy failed event."""
        meta = {"name": "my-policy", "namespace": "default"}
        error_msg = "Invalid policy document"
        
        emit_policy_failed(meta, error_msg)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert error_msg in call_args[1]["message"]
        assert call_args[1]["type"] == "Warning"


class TestAccessKeyEvents:
    """Test cases for access key events."""

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_access_key_created(self, mock_event):
        """Test emitting access key created event."""
        meta = {"name": "my-key", "namespace": "default"}
        key_id = "AKIAIOSFODNN7EXAMPLE"
        
        emit_access_key_created(meta, key_id)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert key_id in call_args[1]["message"]
        assert "created" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"

    @patch("wasabi_s3_operator.utils.events.kopf.event")
    def test_emit_access_key_rotated(self, mock_event):
        """Test emitting access key rotated event."""
        meta = {"name": "my-key", "namespace": "default"}
        key_id = "AKIAIOSFODNN7EXAMPLE"
        
        emit_access_key_rotated(meta, key_id)
        
        assert mock_event.called
        call_args = mock_event.call_args
        assert call_args[0][0] == meta
        assert key_id in call_args[1]["message"]
        assert "rotated" in call_args[1]["message"].lower()
        assert call_args[1]["type"] == "Normal"
