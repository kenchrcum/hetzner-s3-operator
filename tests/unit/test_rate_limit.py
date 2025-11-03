"""Tests for rate limiting utilities."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from kubernetes.client.exceptions import ApiException

from wasabi_s3_operator.utils.rate_limit import (
    handle_rate_limit_error,
    rate_limit_k8s,
    rate_limit_wasabi,
)


class TestRateLimitK8s:
    """Test cases for Kubernetes API rate limiting."""

    def test_rate_limit_k8s_decorator(self):
        """Test that k8s rate limiting decorator works."""
        call_count = 0
        
        @rate_limit_k8s
        def test_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = test_func()
        assert result == "success"
        assert call_count == 1

    def test_rate_limit_k8s_with_args(self):
        """Test rate limiting with function arguments."""
        @rate_limit_k8s
        def test_func(a, b, c=None):
            return f"{a}-{b}-{c}"
        
        result = test_func("x", "y", c="z")
        assert result == "x-y-z"

    @patch("wasabi_s3_operator.utils.rate_limit._K8S_RATE_LIMIT_PER_SECOND", 100.0)
    def test_rate_limit_k8s_enforces_rate(self):
        """Test that rate limiting enforces minimum interval."""
        call_times = []
        
        @rate_limit_k8s
        def test_func():
            call_times.append(time.time())
            return "ok"
        
        # Make multiple calls
        for _ in range(3):
            test_func()
        
        # Check that there's a minimum interval between calls
        # With 100 calls/sec, minimum interval is 0.01 seconds
        assert len(call_times) == 3
        interval1 = call_times[1] - call_times[0]
        interval2 = call_times[2] - call_times[1]
        
        # Intervals should be at least 0.01 seconds (with some tolerance)
        assert interval1 >= 0.009
        assert interval2 >= 0.009

    @patch("wasabi_s3_operator.utils.rate_limit.time.sleep")
    def test_rate_limit_k8s_sleeps_when_needed(self, mock_sleep):
        """Test that rate limiter sleeps when calls are too fast."""
        with patch("wasabi_s3_operator.utils.rate_limit._K8S_RATE_LIMIT_PER_SECOND", 1.0):
            # Reset last call time
            import wasabi_s3_operator.utils.rate_limit as rl
            rl._k8s_last_call_time = 0.0
            
            @rate_limit_k8s
            def test_func():
                return "ok"
            
            # First call shouldn't sleep
            with patch("wasabi_s3_operator.utils.rate_limit.time.time", return_value=10.0):
                test_func()
            
            # Second call very soon after should sleep
            with patch("wasabi_s3_operator.utils.rate_limit.time.time", return_value=10.1):
                test_func()
            
            # Sleep should have been called at least once
            assert mock_sleep.call_count >= 1


class TestRateLimitWasabi:
    """Test cases for Wasabi API rate limiting."""

    def test_rate_limit_wasabi_decorator(self):
        """Test that Wasabi rate limiting decorator works."""
        call_count = 0
        
        @rate_limit_wasabi
        def test_func():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = test_func()
        assert result == "success"
        assert call_count == 1

    def test_rate_limit_wasabi_with_args(self):
        """Test Wasabi rate limiting with function arguments."""
        @rate_limit_wasabi
        def test_func(x, y):
            return x + y
        
        result = test_func(5, 10)
        assert result == 15

    @patch("wasabi_s3_operator.utils.rate_limit._WASABI_RATE_LIMIT_PER_SECOND", 100.0)
    def test_rate_limit_wasabi_enforces_rate(self):
        """Test that Wasabi rate limiting enforces minimum interval."""
        call_times = []
        
        @rate_limit_wasabi
        def test_func():
            call_times.append(time.time())
            return "ok"
        
        # Make multiple calls
        for _ in range(3):
            test_func()
        
        # Check that there's a minimum interval between calls
        assert len(call_times) == 3
        interval1 = call_times[1] - call_times[0]
        interval2 = call_times[2] - call_times[1]
        
        # Intervals should be at least 0.01 seconds (with some tolerance)
        assert interval1 >= 0.009
        assert interval2 >= 0.009


class TestHandleRateLimitError:
    """Test cases for handling rate limit errors."""

    def setup_method(self):
        """Reset retry count before each test."""
        if hasattr(handle_rate_limit_error, "_retry_count"):
            handle_rate_limit_error._retry_count = 0

    def test_handle_429_error(self):
        """Test handling 429 rate limit error."""
        error = ApiException(status=429, reason="Too Many Requests")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep") as mock_sleep:
            result = handle_rate_limit_error(error)
        
        assert result is True
        mock_sleep.assert_called_once()

    def test_handle_503_with_rate_limit(self):
        """Test handling 503 error with rate limit message."""
        error = ApiException(status=503, reason="Service Unavailable: rate limit exceeded")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep") as mock_sleep:
            result = handle_rate_limit_error(error)
        
        assert result is True
        mock_sleep.assert_called_once()

    def test_handle_503_without_rate_limit(self):
        """Test handling 503 error without rate limit message."""
        error = ApiException(status=503, reason="Service Unavailable")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep") as mock_sleep:
            result = handle_rate_limit_error(error)
        
        assert result is False
        mock_sleep.assert_not_called()

    def test_handle_non_rate_limit_error(self):
        """Test handling non-rate-limit errors."""
        error = ApiException(status=404, reason="Not Found")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep") as mock_sleep:
            result = handle_rate_limit_error(error)
        
        assert result is False
        mock_sleep.assert_not_called()

    def test_exponential_backoff(self):
        """Test exponential backoff on retries."""
        error = ApiException(status=429, reason="Too Many Requests")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep") as mock_sleep:
            # First retry - should sleep 1 second
            result1 = handle_rate_limit_error(error)
            assert result1 is True
            assert mock_sleep.call_args_list[0][0][0] == 1  # 2^0 = 1
            
            # Second retry - should sleep 2 seconds
            result2 = handle_rate_limit_error(error)
            assert result2 is True
            assert mock_sleep.call_args_list[1][0][0] == 2  # 2^1 = 2
            
            # Third retry - should sleep 4 seconds
            result3 = handle_rate_limit_error(error)
            assert result3 is True
            assert mock_sleep.call_args_list[2][0][0] == 4  # 2^2 = 4

    def test_max_retries_exceeded(self):
        """Test that max retries limit is enforced."""
        error = ApiException(status=429, reason="Too Many Requests")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep"):
            # Exhaust retries
            for i in range(3):
                result = handle_rate_limit_error(error, max_retries=3)
                assert result is True
            
            # Next attempt should fail
            result = handle_rate_limit_error(error, max_retries=3)
            assert result is False

    def test_retry_count_resets_on_success(self):
        """Test that retry count resets after successful call."""
        rate_limit_error = ApiException(status=429, reason="Too Many Requests")
        other_error = ApiException(status=404, reason="Not Found")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep"):
            # First rate limit error
            handle_rate_limit_error(rate_limit_error)
            
            # Non-rate-limit error resets the counter
            handle_rate_limit_error(other_error)
            
            # Next rate limit error should start from retry 0
            result = handle_rate_limit_error(rate_limit_error)
            assert result is True

    def test_custom_max_retries(self):
        """Test using custom max retries value."""
        error = ApiException(status=429, reason="Too Many Requests")
        
        with patch("wasabi_s3_operator.utils.rate_limit.time.sleep"):
            # With max_retries=1, only 1 retry should succeed
            result1 = handle_rate_limit_error(error, max_retries=1)
            assert result1 is True
            
            result2 = handle_rate_limit_error(error, max_retries=1)
            assert result2 is False
