"""Pytest configuration and fixtures for PipGuard tests."""

import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def mock_pypi_response():
    """Mock PyPI API response for testing."""
    return {
        "info": {
            "name": "test-package",
            "summary": "A test package for unit testing",
            "description": "This package is used for testing PipGuard functionality",
            "home_page": "https://github.com/example/test-package",
            "project_urls": {
                "Repository": "https://github.com/example/test-package"
            },
            "maintainers": [{"name": "Test Author"}],
            "releases": {
                "1.0.0": {
                    "upload_time": "2026-01-01T00:00:00Z"
                }
            }
        }
    }


@pytest.fixture
def mock_malicious_package():
    """Mock malicious package data for testing."""
    return {
        "name": "reqeusts",
        "reason": "Typosquat of 'requests' package",
        "source": "manual",
        "risk_level": "HIGH",
        "added_at": "2026-05-08 10:00:00"
    }
