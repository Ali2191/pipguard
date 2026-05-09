"""Tests for CLI interface."""

import pytest
import asyncio
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock
from pipguard.cli import app


@pytest.fixture
def runner():
    """Create CLI runner for testing."""
    return CliRunner()


def test_install_safe_package(runner):
    """Test installing a safe package."""
    with patch('pipguard.cli.PackageAnalyzer') as mock_analyzer:
        mock_analyzer.return_value.analyze_package = AsyncMock(return_value={
            "package_name": "requests",
            "malicious_info": None,
            "name_analysis": {"typosquats": []},
            "metadata_analysis": {"exists": True}
        })
        
        with patch('pipguard.cli.RiskScorer') as mock_scorer:
            mock_scorer.return_value.calculate_risk_score.return_value = {
                "level": "SAFE",
                "score": 5,
                "reasons": [],
                "recommendation": "✅ No significant risks detected"
            }
            
            result = runner.invoke(app, ["install", "requests"])
            assert result.exit_code == 0
            assert "Installing requests" in result.stdout


def test_install_malicious_package_warning(runner):
    """Test warning for malicious package."""
    with patch('pipguard.cli.PackageAnalyzer') as mock_analyzer:
        mock_analyzer.return_value.analyze_package = AsyncMock(return_value={
            "package_name": "reqeusts",
            "malicious_info": {
                "reason": "Typosquat of 'requests' package",
                "risk_level": "HIGH"
            },
            "name_analysis": {"typosquats": [("requests", 0.9)]}
        })
        
        with patch('pipguard.cli.RiskScorer') as mock_scorer:
            mock_scorer.return_value.calculate_risk_score.return_value = {
                "level": "HIGH",
                "score": 100,
                "reasons": ["Known malicious package: Typosquat of 'requests' package"],
                "recommendation": "⚠️ DO NOT INSTALL - This package shows strong indicators of being malicious"
            }
            
            # Test that warning is shown
            result = runner.invoke(app, ["install", "reqeusts"], input="n\n")
            assert result.exit_code == 1
            assert "Installation cancelled by user" in result.stdout


@pytest.mark.asyncio
async def test_install_force_flag(runner):
    """Test force flag bypasses warnings."""
    with patch('pipguard.cli.PackageAnalyzer') as mock_analyzer:
        mock_analyzer.return_value.analyze_package = AsyncMock(return_value={
            "package_name": "reqeusts",
            "malicious_info": {"reason": "Malicious"},
            "name_analysis": {"typosquats": []}
        })
        
        with patch('pipguard.cli.RiskScorer') as mock_scorer:
            mock_scorer.return_value.calculate_risk_score.return_value = {
                "level": "HIGH",
                "score": 100,
                "reasons": ["Known malicious package"],
                "recommendation": "DO NOT INSTALL"
            }
            
            # Test force flag
            result = runner.invoke(app, ["install", "reqeusts", "--force"])
            assert result.exit_code == 0
            assert "despite HIGH risk" in result.stdout


@pytest.mark.asyncio
async def test_scan_command(runner, tmp_path):
    """Test scan command with requirements file."""
    # Create test requirements file
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\nreqeusts\nnumpy\n")
    
    with patch('pipguard.cli.PackageAnalyzer') as mock_analyzer:
        async def mock_analyze(package_name):
            if package_name == "reqeusts":
                return {
                    "package_name": package_name,
                    "malicious_info": {"reason": "Typosquat"},
                    "name_analysis": {"typosquats": [("requests", 0.9)]}
                }
            else:
                return {
                    "package_name": package_name,
                    "malicious_info": None,
                    "name_analysis": {"typosquats": []}
                }
        
        mock_analyzer.return_value.analyze_package = mock_analyze
        
        with patch('pipguard.cli.RiskScorer') as mock_scorer:
            def mock_score(analysis):
                if analysis["malicious_info"]:
                    return {"level": "HIGH", "score": 100, "reasons": ["Malicious"]}
                else:
                    return {"level": "SAFE", "score": 5, "reasons": []}
            
            mock_scorer.return_value.calculate_risk_score = mock_score
            
            result = runner.invoke(app, ["scan", str(req_file)])
            assert result.exit_code == 0
            assert "Suspicious Packages Found" in result.stdout


@pytest.mark.asyncio
async def test_audit_command(runner, tmp_path):
    """Test audit command."""
    # Create test requirements file
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\nnumpy\n")
    
    with patch('pipguard.cli._get_installed_packages') as mock_packages:
        mock_packages.return_value = ["requests", "numpy", "reqeusts"]
        
        with patch('pipguard.cli.PackageAnalyzer') as mock_analyzer:
            async def mock_analyze(package_name):
                if package_name == "reqeusts":
                    return {
                        "package_name": package_name,
                        "malicious_info": {"reason": "Typosquat"},
                        "name_analysis": {"typosquats": [("requests", 0.9)]}
                    }
                else:
                    return {
                        "package_name": package_name,
                        "malicious_info": None,
                        "name_analysis": {"typosquats": []}
                    }
            
            mock_analyzer.return_value.analyze_package = mock_analyze
            
            with patch('pipguard.cli.RiskScorer') as mock_scorer:
                def mock_score(analysis):
                    if analysis["malicious_info"]:
                        return {"level": "HIGH", "score": 100, "reasons": ["Malicious"]}
                    else:
                        return {"level": "SAFE", "score": 5, "reasons": []}
                
                mock_scorer.return_value.calculate_risk_score = mock_score
                
                result = runner.invoke(app, ["audit", str(tmp_path)])
                assert result.exit_code == 0
                assert "Risky Installed Packages" in result.stdout
