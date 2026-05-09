"""Tests for risk scoring system."""

import pytest
from pipguard.risk_scorer import RiskScorer


@pytest.fixture
def scorer():
    """Create risk scorer instance for testing."""
    return RiskScorer()


def test_high_risk_known_malicious(scorer):
    """Test high risk for known malicious package."""
    analysis = {
        "malicious_info": {
            "reason": "Known malicious package",
            "risk_level": "HIGH"
        }
    }
    
    result = scorer.calculate_risk_score(analysis)
    assert result["level"] == "HIGH"
    assert result["score"] >= 80
    assert any("Known malicious package" in reason for reason in result["reasons"])


def test_medium_risk_typosquat(scorer):
    """Test medium risk for typosquat package."""
    analysis = {
        "name_analysis": {
            "typosquats": [("requests", 0.85)]
        },
        "malicious_info": None
    }
    
    result = scorer.calculate_risk_score(analysis)
    assert result["level"] == "MEDIUM" 
    assert result["score"] >= 50
    assert any("typosquat" in reason for reason in result["reasons"])


def test_low_risk_new_package(scorer):
    """Test low risk for new but legitimate package."""
    analysis = {
        "metadata_analysis": {
            "very_new_package": True,
            "no_description": False
        },
        "malicious_info": None,
        "name_analysis": {"typosquats": []}
    }
    
    result = scorer.calculate_risk_score(analysis)
    assert result["level"] == "LOW"
    assert result["score"] >= 15
    assert "very recently" in str(result["reasons"])


def test_safe_package(scorer):
    """Test safe package scoring."""
    analysis = {
        "malicious_info": None,
        "name_analysis": {"typosquats": []},
        "metadata_analysis": {
            "very_new_package": False,
            "no_description": False,
            "suspicious_description": False
        }
    }
    
    result = scorer.calculate_risk_score(analysis)
    assert result["level"] == "SAFE"
    assert result["score"] < 15


def test_risk_level_boundaries(scorer):
    """Test risk level boundaries."""
    # Test HIGH boundary
    high_analysis = {"malicious_info": {"reason": "test"}}
    high_result = scorer.calculate_risk_score(high_analysis)
    assert high_result["level"] == "HIGH"
    
    # Test MEDIUM boundary  
    medium_analysis = {"name_analysis": {"typosquats": [("test", 0.85)]}}
    medium_result = scorer.calculate_risk_score(medium_analysis)
    assert medium_result["level"] == "MEDIUM"
    
    # Test SAFE boundary
    safe_analysis = {}
    safe_result = scorer.calculate_risk_score(safe_analysis)
    assert safe_result["level"] == "SAFE"


def test_recommendations(scorer):
    """Test risk recommendations."""
    # Test HIGH recommendation
    high_result = scorer._get_recommendation("HIGH")
    assert "DO NOT INSTALL" in high_result
    
    # Test SAFE recommendation
    safe_result = scorer._get_recommendation("SAFE")
    assert "No significant risks" in safe_result
