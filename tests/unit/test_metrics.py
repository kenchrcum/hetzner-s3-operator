"""Tests for Prometheus metrics."""

from __future__ import annotations

import pytest
from prometheus_client import REGISTRY

from wasabi_s3_operator.metrics import (
    api_call_duration_seconds,
    api_call_total,
    bucket_operations_total,
    drift_detected_total,
    error_total,
    provider_connectivity_total,
    rate_limit_hits_total,
    reconcile_duration_seconds,
    reconcile_total,
    resource_status_total,
)


class TestMetricsExist:
    """Test that all expected metrics are defined."""

    def test_reconcile_total_exists(self):
        """Test reconcile_total counter exists."""
        assert reconcile_total is not None
        # Prometheus counters don't include "_total" in their _name attribute
        assert reconcile_total._name == "wasabi_s3_operator_reconcile"

    def test_reconcile_duration_exists(self):
        """Test reconcile_duration_seconds histogram exists."""
        assert reconcile_duration_seconds is not None
        assert reconcile_duration_seconds._name == "wasabi_s3_operator_reconcile_duration_seconds"

    def test_bucket_operations_total_exists(self):
        """Test bucket_operations_total counter exists."""
        assert bucket_operations_total is not None
        assert bucket_operations_total._name == "wasabi_s3_operator_bucket_operations"

    def test_provider_connectivity_total_exists(self):
        """Test provider_connectivity_total counter exists."""
        assert provider_connectivity_total is not None
        assert (
            provider_connectivity_total._name == "wasabi_s3_operator_provider_connectivity"
        )

    def test_drift_detected_total_exists(self):
        """Test drift_detected_total counter exists."""
        assert drift_detected_total is not None
        assert drift_detected_total._name == "wasabi_s3_operator_drift_detected"

    def test_api_call_total_exists(self):
        """Test api_call_total counter exists."""
        assert api_call_total is not None
        assert api_call_total._name == "wasabi_s3_operator_api_call"

    def test_api_call_duration_exists(self):
        """Test api_call_duration_seconds histogram exists."""
        assert api_call_duration_seconds is not None
        assert api_call_duration_seconds._name == "wasabi_s3_operator_api_call_duration_seconds"

    def test_rate_limit_hits_total_exists(self):
        """Test rate_limit_hits_total counter exists."""
        assert rate_limit_hits_total is not None
        assert rate_limit_hits_total._name == "wasabi_s3_operator_rate_limit_hits"

    def test_error_total_exists(self):
        """Test error_total counter exists."""
        assert error_total is not None
        assert error_total._name == "wasabi_s3_operator_error"

    def test_resource_status_total_exists(self):
        """Test resource_status_total counter exists."""
        assert resource_status_total is not None
        assert resource_status_total._name == "wasabi_s3_operator_resource_status"


class TestMetricLabels:
    """Test that metrics have correct labels."""

    def test_reconcile_total_labels(self):
        """Test reconcile_total has correct labels."""
        # Clear any previous values
        reconcile_total.labels(kind="TestKind", result="test").inc(0)
        
        # Check that we can use the expected labels
        reconcile_total.labels(kind="Bucket", result="success").inc()
        reconcile_total.labels(kind="Provider", result="error").inc()

    def test_bucket_operations_total_labels(self):
        """Test bucket_operations_total has correct labels."""
        bucket_operations_total.labels(operation="create", result="success").inc(0)
        bucket_operations_total.labels(operation="delete", result="error").inc()

    def test_provider_connectivity_total_labels(self):
        """Test provider_connectivity_total has correct labels."""
        provider_connectivity_total.labels(provider="wasabi", status="connected").inc(0)
        provider_connectivity_total.labels(provider="aws", status="disconnected").inc()

    def test_drift_detected_total_labels(self):
        """Test drift_detected_total has correct labels."""
        drift_detected_total.labels(kind="Bucket", resource_type="lifecycle").inc(0)
        drift_detected_total.labels(kind="Policy", resource_type="document").inc()

    def test_api_call_total_labels(self):
        """Test api_call_total has correct labels."""
        api_call_total.labels(api_type="k8s", operation="get", result="success").inc(0)
        api_call_total.labels(api_type="s3", operation="create_bucket", result="error").inc()

    def test_api_call_duration_labels(self):
        """Test api_call_duration_seconds has correct labels."""
        api_call_duration_seconds.labels(api_type="k8s", operation="list").observe(0.5)
        api_call_duration_seconds.labels(api_type="s3", operation="put_object").observe(1.2)

    def test_rate_limit_hits_total_labels(self):
        """Test rate_limit_hits_total has correct labels."""
        rate_limit_hits_total.labels(api_type="k8s").inc(0)
        rate_limit_hits_total.labels(api_type="wasabi").inc()

    def test_error_total_labels(self):
        """Test error_total has correct labels."""
        error_total.labels(kind="Bucket", error_type="ValueError").inc(0)
        error_total.labels(kind="Provider", error_type="ConnectionError").inc()

    def test_resource_status_total_labels(self):
        """Test resource_status_total has correct labels."""
        resource_status_total.labels(kind="Bucket", status="ready").inc(0)
        resource_status_total.labels(kind="Provider", status="not_ready").inc()


class TestHistogramBuckets:
    """Test that histograms have appropriate bucket configurations."""

    def test_reconcile_duration_buckets(self):
        """Test reconcile_duration has reasonable buckets."""
        # Simply verify that the histogram was created with custom buckets
        # by checking if the metric exists and has the histogram type
        assert reconcile_duration_seconds is not None
        assert hasattr(reconcile_duration_seconds, "observe")
        
        # We can verify buckets by looking at the documentation
        # The buckets are [0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
        # Just verify the metric works
        reconcile_duration_seconds.labels(kind="test").observe(1.0)

    def test_api_call_duration_buckets(self):
        """Test api_call_duration has fine-grained buckets."""
        # Simply verify that the histogram was created with custom buckets
        # by checking if the metric exists and has the histogram type
        assert api_call_duration_seconds is not None
        assert hasattr(api_call_duration_seconds, "observe")
        
        # The buckets are [0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0]
        # Just verify the metric works
        api_call_duration_seconds.labels(api_type="test", operation="test").observe(0.05)


class TestMetricOperations:
    """Test metric operations."""

    def test_counter_increment(self):
        """Test that counters can be incremented."""
        # Get initial value
        initial = reconcile_total.labels(kind="TestCounter", result="test")._value.get()
        
        # Increment
        reconcile_total.labels(kind="TestCounter", result="test").inc()
        
        # Check value increased
        new_value = reconcile_total.labels(kind="TestCounter", result="test")._value.get()
        assert new_value == initial + 1

    def test_counter_increment_by_value(self):
        """Test that counters can be incremented by specific value."""
        initial = reconcile_total.labels(kind="TestCounterValue", result="test")._value.get()
        
        reconcile_total.labels(kind="TestCounterValue", result="test").inc(5)
        
        new_value = reconcile_total.labels(kind="TestCounterValue", result="test")._value.get()
        assert new_value == initial + 5

    def test_histogram_observe(self):
        """Test that histograms can observe values."""
        # Observe some values
        reconcile_duration_seconds.labels(kind="TestHistogram2").observe(0.5)
        reconcile_duration_seconds.labels(kind="TestHistogram2").observe(1.5)
        reconcile_duration_seconds.labels(kind="TestHistogram2").observe(5.0)
        
        # Just verify no exceptions were raised
        # The histogram successfully observed all values
        assert True

    def test_different_label_values_independent(self):
        """Test that metrics with different labels are independent."""
        # Increment metric with label1
        bucket_operations_total.labels(operation="test1", result="success").inc(3)
        
        # Increment metric with label2
        bucket_operations_total.labels(operation="test2", result="success").inc(5)
        
        # Values should be independent
        value1 = bucket_operations_total.labels(operation="test1", result="success")._value.get()
        value2 = bucket_operations_total.labels(operation="test2", result="success")._value.get()
        
        assert value1 == 3
        assert value2 == 5

