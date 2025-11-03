"""Handler modules for CRD resources (Hetzner-specific)."""

# Import handlers to register them - all handlers register themselves via @kopf decorators
from . import bucket  # noqa: F401
from . import bucket_policy  # noqa: F401
from . import provider  # noqa: F401

