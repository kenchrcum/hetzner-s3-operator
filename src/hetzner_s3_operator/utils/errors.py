"""Error sanitization utilities to prevent information leakage."""

import re
from typing import Any


# Patterns that might expose sensitive information
SENSITIVE_PATTERNS = [
    r"endpoint[:\s]+([a-zA-Z0-9\-\.]+)",
    r"region[:\s]+([a-zA-Z0-9\-]+)",
    r"access[_\s]?key[_\s]?id[:\s]+([A-Z0-9]{20})",
    r"secret[_\s]?access[_\s]?key[:\s]+([A-Za-z0-9/+=]{40})",
    r"session[_\s]?token[:\s]+([A-Za-z0-9/+=]+)",
    r"arn:aws:iam::\d+:user/([a-zA-Z0-9\-_]+)",
    r"arn:aws:s3:::([a-zA-Z0-9\-_\.]+)",
    r"bucket[_\s]?name[:\s]+([a-zA-Z0-9\-_\.]+)",
    r"provider[_\s]?name[:\s]+([a-zA-Z0-9\-_]+)",
    r"user[_\s]?name[:\s]+([a-zA-Z0-9\-_]+)",
    r"namespace[:\s]+([a-zA-Z0-9\-_]+)",
]

# Fields to redact completely
SENSITIVE_FIELDS = {
    "access_key_id",
    "secret_access_key",
    "session_token",
    "password",
    "secret",
    "credentials",
    "token",
    "key",
}


def sanitize_error_message(message: str) -> str:
    """Sanitize error message to remove sensitive information.
    
    Args:
        message: Original error message
        
    Returns:
        Sanitized error message with sensitive data redacted
    """
    sanitized = message
    
    # Replace sensitive patterns
    for pattern in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, r"\1 [REDACTED]", sanitized, flags=re.IGNORECASE)
    
    # Redact common sensitive field names
    for field in SENSITIVE_FIELDS:
        # Replace field: value patterns
        sanitized = re.sub(
            rf"{field}[:\s]+([^\s,;\)]+)",
            rf"{field}: [REDACTED]",
            sanitized,
            flags=re.IGNORECASE,
        )
    
    return sanitized


def sanitize_exception(error: Exception) -> str:
    """Sanitize exception message.
    
    Args:
        error: Exception object
        
    Returns:
        Sanitized error message
    """
    error_msg = str(error)
    return sanitize_error_message(error_msg)


def sanitize_dict(data: dict[str, Any], sensitive_keys: set[str] | None = None) -> dict[str, Any]:
    """Sanitize dictionary by redacting sensitive fields.
    
    Args:
        data: Dictionary to sanitize
        sensitive_keys: Additional keys to redact (merged with SENSITIVE_FIELDS)
        
    Returns:
        Sanitized dictionary with sensitive values redacted
    """
    if sensitive_keys is None:
        sensitive_keys = set()
    
    all_sensitive = SENSITIVE_FIELDS | sensitive_keys
    sanitized = {}
    
    for key, value in data.items():
        key_lower = key.lower()
        # Check if any sensitive field matches this key
        if any(sensitive in key_lower for sensitive in all_sensitive):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value, sensitive_keys)
        elif isinstance(value, str):
            sanitized[key] = sanitize_error_message(value)
        else:
            sanitized[key] = value
    
    return sanitized

