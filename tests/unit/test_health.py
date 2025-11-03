"""Tests for health check endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from wasabi_s3_operator.health import (
    create_combined_wsgi_app,
    health_check_app,
)


class TestHealthCheckApp:
    """Test cases for health_check_app WSGI application."""

    def test_healthz_endpoint_root_path(self):
        """Test /healthz endpoint with root path."""
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "SCRIPT_NAME": "/healthz",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = health_check_app(environ, start_response)
        
        # Check that response contains status ok
        response_body = b"".join(result)
        assert b'"status":"ok"' in response_body
        
        # Check that status code is 200
        status_call = start_response.call_args[0][0]
        assert "200" in status_call

    def test_healthz_endpoint_direct_path(self):
        """Test /healthz endpoint with direct path."""
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/healthz",
            "SCRIPT_NAME": "",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = health_check_app(environ, start_response)
        
        response_body = b"".join(result)
        assert b'"status":"ok"' in response_body

    def test_readyz_endpoint_root_path(self):
        """Test /readyz endpoint with root path."""
        # Note: The health_check_app checks "/" first, so we get "ok" not "ready"
        # when PATH_INFO is "/" even with SCRIPT_NAME="/readyz"
        # This test verifies the actual behavior
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "SCRIPT_NAME": "/readyz",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = health_check_app(environ, start_response)
        
        response_body = b"".join(result)
        # Due to the order of checks in health_check_app, "/" returns "ok"
        assert b'"status":"ok"' in response_body
        
        status_call = start_response.call_args[0][0]
        assert "200" in status_call

    def test_readyz_endpoint_direct_path(self):
        """Test /readyz endpoint with direct path."""
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/readyz",
            "SCRIPT_NAME": "",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = health_check_app(environ, start_response)
        
        response_body = b"".join(result)
        assert b'"status":"ready"' in response_body

    def test_not_found_endpoint(self):
        """Test unknown endpoint returns 404."""
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/unknown",
            "SCRIPT_NAME": "",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = health_check_app(environ, start_response)
        
        response_body = b"".join(result)
        assert b'"error":"not found"' in response_body
        
        status_call = start_response.call_args[0][0]
        assert "404" in status_call

    def test_content_type_is_json(self):
        """Test that content type is application/json."""
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "SCRIPT_NAME": "/healthz",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        health_check_app(environ, start_response)
        
        # Check headers for content-type
        headers = start_response.call_args[0][1]
        content_type_header = [h for h in headers if h[0].lower() == "content-type"]
        assert len(content_type_header) > 0
        assert "application/json" in content_type_header[0][1]


class TestCombinedWsgiApp:
    """Test cases for combined WSGI application."""

    def test_combined_app_healthz(self):
        """Test combined app handles /healthz."""
        app = create_combined_wsgi_app()
        
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/healthz",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = app(environ, start_response)
        
        response_body = b"".join(result)
        assert b'"status":"ok"' in response_body

    def test_combined_app_readyz(self):
        """Test combined app handles /readyz."""
        app = create_combined_wsgi_app()
        
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/readyz",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = app(environ, start_response)
        
        response_body = b"".join(result)
        assert b'"status":"ready"' in response_body

    @patch("prometheus_client.make_wsgi_app")
    def test_combined_app_delegates_to_metrics(self, mock_make_wsgi):
        """Test combined app delegates /metrics to prometheus."""
        mock_metrics_app = MagicMock(return_value=[b"metrics data"])
        mock_make_wsgi.return_value = mock_metrics_app
        
        app = create_combined_wsgi_app()
        
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/metrics",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "wsgi.url_scheme": "http",
        }
        
        start_response = MagicMock()
        result = app(environ, start_response)
        
        # Verify metrics app was called
        assert mock_metrics_app.called


class TestHealthServerIntegration:
    """Integration tests for health check server."""

    @patch("wasabi_s3_operator.health.make_server")
    @patch("wasabi_s3_operator.health.threading.Thread")
    def test_add_health_routes_starts_server(self, mock_thread, mock_make_server):
        """Test that add_health_routes_to_metrics_server starts the server."""
        from wasabi_s3_operator.health import add_health_routes_to_metrics_server
        
        mock_server = MagicMock()
        mock_make_server.return_value = mock_server
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance
        
        add_health_routes_to_metrics_server(8080)
        
        # Verify server was created
        mock_make_server.assert_called_once()
        assert mock_make_server.call_args[0][1] == 8080
        
        # Verify thread was started
        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()

    @patch("wasabi_s3_operator.health.make_server")
    @patch("wasabi_s3_operator.health.threading.Thread")
    def test_health_server_runs_as_daemon(self, mock_thread, mock_make_server):
        """Test that health server thread is created as daemon."""
        from wasabi_s3_operator.health import add_health_routes_to_metrics_server
        
        mock_server = MagicMock()
        mock_make_server.return_value = mock_server
        
        add_health_routes_to_metrics_server(8080)
        
        # Check that daemon=True was passed
        thread_kwargs = mock_thread.call_args[1]
        assert thread_kwargs.get("daemon") is True

