"""Unit tests for condition utilities."""

from __future__ import annotations

from wasabi_s3_operator.utils.conditions import (
    set_auth_valid_condition,
    set_endpoint_reachable_condition,
    set_ready_condition,
    update_condition,
)


class TestConditions:
    """Test condition utilities."""

    def test_update_condition_new(self) -> None:
        """Test adding a new condition."""
        conditions = []
        result = update_condition(
            conditions, "TestCondition", "True", "TestReason", "Test message", observed_generation=1
        )

        assert len(result) == 1
        assert result[0]["type"] == "TestCondition"
        assert result[0]["status"] == "True"
        assert result[0]["reason"] == "TestReason"
        assert result[0]["message"] == "Test message"
        assert result[0]["observedGeneration"] == 1

    def test_update_condition_existing(self) -> None:
        """Test updating an existing condition."""
        conditions = [
            {
                "type": "TestCondition",
                "status": "False",
                "reason": "OldReason",
                "message": "Old message",
                "lastTransitionTime": "2023-01-01T00:00:00Z",
            }
        ]

        result = update_condition(
            conditions, "TestCondition", "True", "NewReason", "New message", observed_generation=2
        )

        assert len(result) == 1
        assert result[0]["status"] == "True"
        assert result[0]["reason"] == "NewReason"
        assert result[0]["message"] == "New message"
        assert result[0]["observedGeneration"] == 2

    def test_set_ready_condition(self) -> None:
        """Test setting ready condition."""
        conditions = []
        result = set_ready_condition(conditions, True, "Ready", observed_generation=1)

        assert len(result) == 1
        assert result[0]["type"] == "Ready"
        assert result[0]["status"] == "True"

    def test_set_auth_valid_condition(self) -> None:
        """Test setting auth valid condition."""
        conditions = []
        result = set_auth_valid_condition(conditions, True, "Auth valid", observed_generation=1)

        assert len(result) == 1
        assert result[0]["type"] == "AuthValid"
        assert result[0]["status"] == "True"

    def test_set_endpoint_reachable_condition(self) -> None:
        """Test setting endpoint reachable condition."""
        conditions = []
        result = set_endpoint_reachable_condition(conditions, True, "Reachable", observed_generation=1)

        assert len(result) == 1
        assert result[0]["type"] == "EndpointReachable"
        assert result[0]["status"] == "True"

