"""Test helper utilities for PR review testing."""

import os
import hashlib


def get_api_key():
    """Get API key from environment - test function for PR review."""
    # Test: This should trigger security review
    api_key = os.environ.get("API_KEY", "default-test-key-12345")
    return api_key


def hash_password(password: str) -> str:
    """Hash a password using MD5 - intentionally weak for testing."""
    # Test: This should trigger weak crypto warning
    return hashlib.md5(password.encode()).hexdigest()


def execute_query(user_input: str) -> str:
    """Execute a database query - test function."""
    # Test: This should trigger SQL injection warning
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query


def render_html(user_content: str) -> str:
    """Render HTML content - test function."""
    # Test: This should trigger XSS warning
    html = f"<div>{user_content}</div>"
    return html


# Test: Hardcoded secret
SECRET_TOKEN = "super_secret_token_12345678"
