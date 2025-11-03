"""Health check endpoint for the operator."""

from typing import Any
from werkzeug.wrappers import Request, Response
from werkzeug.serving import make_server
import threading


def health_check_app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
    """WSGI application for health check endpoints.
    
    Note: When mounted via DispatcherMiddleware, the path prefix is stripped,
    so '/healthz' becomes '/' when passed to this function.
    """
    request = Request(environ)
    path = request.path
    
    # When mounted under /healthz or /readyz, DispatcherMiddleware strips the prefix
    # So we check for root path or check the SCRIPT_NAME to determine which endpoint
    script_name = environ.get("SCRIPT_NAME", "")
    
    if path == "/" or path == "/healthz" or script_name == "/healthz":
        response = Response('{"status":"ok"}', mimetype="application/json", status=200)
    elif path == "/readyz" or script_name == "/readyz":
        # Readiness check - can add more sophisticated checks here
        response = Response('{"status":"ready"}', mimetype="application/json", status=200)
    else:
        response = Response('{"error":"not found"}', mimetype="application/json", status=404)
    
    return response(environ, start_response)


def add_health_routes_to_metrics_server(port: int) -> None:
    """Add health check routes to the metrics server.
    
    This creates a wrapper WSGI app that handles /healthz and /readyz routes,
    and delegates /metrics to prometheus_client's WSGI app.
    
    Args:
        port: Port number for the health check server (must be different from metrics port)
    """
    # Start a simple health check server on a separate port
    # The deployment will need to be updated to use this port for health checks
    # Or we can integrate it into the metrics server using DispatcherMiddleware
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    from prometheus_client import make_wsgi_app
    
    metrics_app = make_wsgi_app()
    
    # Create combined app with health checks
    combined_app = DispatcherMiddleware(
        metrics_app,
        {
            "/healthz": health_check_app,
            "/readyz": health_check_app,
        }
    )
    
    # Start server in background thread
    server = make_server("", port, combined_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()


def create_combined_wsgi_app() -> Any:
    """Create a WSGI app that combines metrics and health check endpoints.
    
    Returns:
        Combined WSGI application
    """
    from prometheus_client import make_wsgi_app
    
    metrics_app = make_wsgi_app()
    
    def combined_app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        """WSGI app that routes /healthz and /readyz, delegates /metrics to prometheus."""
        path = environ.get("PATH_INFO", "")
        
        # Handle health check endpoints
        if path == "/healthz":
            response = Response('{"status":"ok"}', mimetype="application/json", status=200)
            return response(environ, start_response)
        elif path == "/readyz":
            response = Response('{"status":"ready"}', mimetype="application/json", status=200)
            return response(environ, start_response)
        else:
            # Delegate all other paths (including /metrics) to prometheus app
            return metrics_app(environ, start_response)
    
    return combined_app

