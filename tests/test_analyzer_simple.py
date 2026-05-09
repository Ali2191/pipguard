"""Simple tests for analyzer module without async fixtures."""

import pytest
from pipguard.analyzer import PackageAnalyzer
from pipguard.database import MaliciousPackageDB


@pytest.fixture
def analyzer():
    """Create analyzer instance for testing."""
    db = MaliciousPackageDB()
    db.load_initial_data()
    return PackageAnalyzer(db)


def test_detect_typosquatting(analyzer):
    """Test typosquatting detection."""
    # Test obvious typosquat
    typosquats = analyzer.detect_typosquatting("reqeusts")
    assert len(typosquats) > 0
    assert typosquats[0][0] == "requests"
    assert typosquats[0][1] > 0.7
    
    # Test legitimate package
    typosquats = analyzer.detect_typosquatting("numpy")
    assert len(typosquats) == 0


def test_suspicious_patterns(analyzer):
    """Test suspicious pattern detection."""
    # Test crypto-related suspicious name
    patterns = analyzer.check_suspicious_patterns("crypto-miner-tool")
    assert len(patterns) > 0
    
    # Test legitimate name
    patterns = analyzer.check_suspicious_patterns("requests")
    assert len(patterns) == 0


def test_name_analysis(analyzer):
    """Test package name analysis."""
    analysis = analyzer.analyze_name("test-package")
    
    # Should have no typosquats for legitimate name
    assert "typosquats" in analysis
    assert len(analysis["typosquats"]) == 0
    
    # Should detect suspicious patterns
    analysis_mining = analyzer.analyze_name("crypto-miner")
    assert "suspicious_patterns" in analysis
    assert len(analysis["suspicious_patterns"]) > 0


def test_pypi_metadata_analysis(analyzer):
    """Test PyPI metadata analysis."""
    # Test with missing package
    metadata = analyzer._analyze_pypi_metadata(None)
    assert metadata["exists"] is False
    
    # Test with fake package data
    fake_pypi_info = {
        "info": {
            "summary": "A test package",
            "description": "This is a test package for demonstration purposes",
            "home_page": "https://example.com",
            "project_urls": {"Repository": "https://github.com/example/test"},
            "maintainers": [{"name": "Test Author"}],
            "releases": {
                "1.0.0": {
                    "upload_time": "2026-05-08T10:00:00Z"
                }
            }
        }
    }
    metadata = analyzer._analyze_pypi_metadata(fake_pypi_info)
    assert metadata["exists"] is True
    assert "very_new_package" in metadata
