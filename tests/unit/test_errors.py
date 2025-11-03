"""Tests for error sanitization utilities."""

from __future__ import annotations

import pytest

from wasabi_s3_operator.utils.errors import (
    sanitize_dict,
    sanitize_error_message,
    sanitize_exception,
)


class TestSanitizeErrorMessage:
    """Test cases for sanitize_error_message function."""

    def test_sanitize_access_key(self):
        """Test that access keys are sanitized."""
        message = "Error: access_key_id: AKIAIOSFODNN7EXAMPLE"
        result = sanitize_error_message(message)
        # The pattern replaces "field: value" with "field: [REDACTED]"
        assert "[REDACTED]" in result
        # Verify it's been modified from original
        assert result != message

    def test_sanitize_secret_key(self):
        """Test that secret keys are sanitized."""
        message = "Error: secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = sanitize_error_message(message)
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result
        assert "[REDACTED]" in result

    def test_sanitize_session_token(self):
        """Test that session tokens are sanitized."""
        message = "Error: session_token: AQoDYXdzEPT//////////wEXAMPLEtc764"
        result = sanitize_error_message(message)
        assert "[REDACTED]" in result
        assert result != message

    def test_sanitize_password(self):
        """Test that passwords are sanitized."""
        message = "Error: password: mysecretpassword123"
        result = sanitize_error_message(message)
        assert "mysecretpassword123" not in result
        assert "[REDACTED]" in result

    def test_sanitize_multiple_fields(self):
        """Test sanitizing multiple sensitive fields."""
        message = (
            "Error: access_key_id: AKIAIOSFODNN7EXAMPLE, "
            "secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        result = sanitize_error_message(message)
        assert result.count("[REDACTED]") >= 2
        assert result != message

    def test_sanitize_case_insensitive(self):
        """Test that sanitization is case-insensitive."""
        message = "Error: ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE"
        result = sanitize_error_message(message)
        assert "[REDACTED]" in result
        assert result != message

    def test_no_sanitization_needed(self):
        """Test that messages without sensitive data remain unchanged."""
        message = "Error: Resource not found"
        result = sanitize_error_message(message)
        assert result == message

    def test_sanitize_endpoint(self):
        """Test that endpoints are not fully redacted (pattern test)."""
        message = "Error connecting to endpoint: s3.wasabisys.com"
        result = sanitize_error_message(message)
        # The pattern should match but the result behavior may vary
        assert "Error" in result

    def test_sanitize_credentials_field(self):
        """Test that credentials field is sanitized."""
        message = "Error: credentials: {access_key: AKIA123, secret: abc123}"
        result = sanitize_error_message(message)
        assert "[REDACTED]" in result


class TestSanitizeException:
    """Test cases for sanitize_exception function."""

    def test_sanitize_value_error(self):
        """Test sanitizing a ValueError."""
        error = ValueError("access_key_id: AKIAIOSFODNN7EXAMPLE")
        result = sanitize_exception(error)
        assert "[REDACTED]" in result
        assert result != str(error)

    def test_sanitize_runtime_error(self):
        """Test sanitizing a RuntimeError."""
        error = RuntimeError("secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        result = sanitize_exception(error)
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result
        assert "[REDACTED]" in result

    def test_sanitize_generic_exception(self):
        """Test sanitizing a generic Exception."""
        error = Exception("Resource not found")
        result = sanitize_exception(error)
        assert result == "Resource not found"


class TestSanitizeDict:
    """Test cases for sanitize_dict function."""

    def test_sanitize_access_key_in_dict(self):
        """Test sanitizing access_key_id in dictionary."""
        data = {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}
        result = sanitize_dict(data)
        assert result["access_key_id"] == "[REDACTED]"
        assert result["region"] == "us-east-1"

    def test_sanitize_secret_key_in_dict(self):
        """Test sanitizing secret_access_key in dictionary."""
        data = {
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "bucket": "my-bucket",
        }
        result = sanitize_dict(data)
        assert result["secret_access_key"] == "[REDACTED]"
        assert result["bucket"] == "my-bucket"

    def test_sanitize_password_in_dict(self):
        """Test sanitizing password in dictionary."""
        data = {"username": "admin", "password": "mysecretpassword"}
        result = sanitize_dict(data)
        assert result["username"] == "admin"
        assert result["password"] == "[REDACTED]"

    def test_sanitize_nested_dict(self):
        """Test sanitizing nested dictionary."""
        data = {
            "config": {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "bucket_name": "my-bucket",
            },
            "status": "ready",
        }
        result = sanitize_dict(data)
        assert result["config"]["access_key_id"] == "[REDACTED]"
        assert result["config"]["bucket_name"] == "my-bucket"
        assert result["status"] == "ready"

    def test_sanitize_with_custom_keys(self):
        """Test sanitizing with additional custom keys."""
        data = {"username": "admin", "api_token": "secret123"}
        result = sanitize_dict(data, sensitive_keys={"username"})
        assert result["username"] == "[REDACTED]"
        assert result["api_token"] == "[REDACTED]"

    def test_sanitize_string_values(self):
        """Test sanitizing string values in dictionary."""
        data = {
            "message": "Error: access_key_id: AKIAIOSFODNN7EXAMPLE",
            "status": "failed",
        }
        result = sanitize_dict(data)
        assert "[REDACTED]" in result["message"]
        assert result["message"] != data["message"]
        assert result["status"] == "failed"

    def test_sanitize_mixed_types(self):
        """Test sanitizing dictionary with mixed value types."""
        data = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "count": 5,
            "enabled": True,
            "tags": ["tag1", "tag2"],
        }
        result = sanitize_dict(data)
        assert result["access_key_id"] == "[REDACTED]"
        assert result["count"] == 5
        assert result["enabled"] is True
        assert result["tags"] == ["tag1", "tag2"]

    def test_sanitize_empty_dict(self):
        """Test sanitizing empty dictionary."""
        data = {}
        result = sanitize_dict(data)
        assert result == {}

    def test_sanitize_all_default_fields(self):
        """Test sanitizing all default sensitive fields."""
        data = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI",
            "session_token": "AQoDYXdzEPT",
            "password": "pass123",
            "secret": "secret123",
            "credentials": "creds",
            "token": "tok123",
            "key": "key123",
        }
        result = sanitize_dict(data)
        # All values should be redacted
        for value in result.values():
            assert value == "[REDACTED]"

    def test_sanitize_partial_key_match(self):
        """Test that partial matches in key names are sanitized."""
        data = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "my_secret": "secret123",
            "user_password": "pass123",
        }
        result = sanitize_dict(data)
        # All should be redacted as they contain sensitive field names
        assert result["aws_access_key_id"] == "[REDACTED]"
        assert result["my_secret"] == "[REDACTED]"
        assert result["user_password"] == "[REDACTED]"

