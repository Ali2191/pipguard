"""
PipGuard - A security tool to prevent accidental installation of malicious AI-generated packages.
"""

__version__ = "0.1.0"
__author__ = "PipGuard Team"
__email__ = "team@pipguard.dev"

from .cli import main
from .analyzer import PackageAnalyzer
from .database import MaliciousPackageDB
from .risk_scorer import RiskScorer

__all__ = [
    "main",
    "PackageAnalyzer", 
    "MaliciousPackageDB",
    "RiskScorer"
]

if __name__ == "__main__":
    main()
