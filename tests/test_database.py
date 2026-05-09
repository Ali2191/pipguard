"""Tests for malicious package database."""

import pytest
import tempfile
from pathlib import Path
from pipguard.database import MaliciousPackageDB


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_file:
        db_path = Path(tmp_file.name)
        yield db_path
        # Cleanup
        if db_path.exists():
            db_path.unlink()


def test_database_initialization(temp_db):
    """Test database initialization."""
    db = MaliciousPackageDB(temp_db)
    assert db.db_path == temp_db
    assert temp_db.exists()


def test_add_malicious_package(temp_db):
    """Test adding malicious packages."""
    db = MaliciousPackageDB(temp_db)
    
    # Add a malicious package
    db.add_malicious_package("test-malicious", "Test package", "unit-test", "HIGH")
    
    # Check it was added
    result = db.is_malicious("test-malicious")
    assert result is not None
    assert result["name"] == "test-malicious"
    assert result["reason"] == "Test package"
    assert result["risk_level"] == "HIGH"


def test_is_malicious_not_found(temp_db):
    """Test checking non-malicious package."""
    db = MaliciousPackageDB(temp_db)
    
    result = db.is_malicious("safe-package")
    assert result is None


def test_case_insensitive_lookup(temp_db):
    """Test case-insensitive package lookup."""
    db = MaliciousPackageDB(temp_db)
    
    # Add uppercase package name
    db.add_malicious_package("MALICIOUS-PACKAGE", "Test", "unit-test", "HIGH")
    
    # Check lowercase lookup
    result = db.is_malicious("malicious-package")
    assert result is not None
    assert result["name"] == "malicious-package"


def test_load_initial_data(temp_db):
    """Test loading initial malicious package data."""
    db = MaliciousPackageDB(temp_db)
    db.load_initial_data()
    
    # Check that initial packages were loaded
    assert db.is_malicious("reqeusts") is not None
    assert db.is_malicious("urlib3") is not None
    assert db.is_malicious("fake-crypto") is not None
