"""
Package analysis module for detecting suspicious patterns and typosquatting.
"""

import re
from typing import Dict, List, Tuple, Optional
from rapidfuzz import fuzz
from .database import MaliciousPackageDB


class PackageAnalyzer:
    """Analyzes package names and metadata for suspicious patterns."""
    
    def __init__(self, db: MaliciousPackageDB):
        """Initialize analyzer with malicious package database."""
        self.db = db
        
        # Popular packages for typosquatting detection
        self.popular_packages = {
            "requests", "numpy", "pandas", "tensorflow", "pytorch", "scikit-learn",
            "matplotlib", "flask", "django", "fastapi", "sqlalchemy", "beautifulsoup4",
            "selenium", "pillow", "opencv-python", "plotly", "streamlit", "gradio",
            "transformers", "torch", "keras", "pytest", "black", "mypy", "pylint",
            "urllib3", "certifi", "charset-normalizer", "idna", "click", "rich",
            "typer", "httpx", "aiohttp", "asyncio", "websockets", "cryptography",
            "hashlib", "json", "yaml", "toml", "setuptools", "wheel", "pip"
        }
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r".*crypto.*",  # Generic crypto packages
            r".*hack.*",   # Hack tools
            r".*crack.*",  # Crack tools  
            r".*steal.*",  # Stealing tools
            r".*keylog.*", # Keyloggers
            r".*miner.*",  # Crypto miners
            r".*backdoor.*", # Backdoors
            r".*rat.*",     # Remote access tools
        ]
    
    def calculate_similarity(self, name1: str, name2: str) -> float:
        """Calculate string similarity ratio."""
        return fuzz.ratio(name1.lower(), name2.lower())
    
    def detect_typosquatting(self, package_name: str) -> List[Tuple[str, float]]:
        """Detect if package name is a typosquat of popular packages."""
        typosquats = []
        
        for popular in self.popular_packages:
            similarity = self.calculate_similarity(package_name, popular)
            if similarity > 0.7 and similarity < 1.0:  # Similar but not identical
                typosquats.append((popular, similarity))
        
        return sorted(typosquats, key=lambda x: x[1], reverse=True)
    
    def check_suspicious_patterns(self, package_name: str) -> List[str]:
        """Check if package name matches suspicious patterns."""
        matched_patterns = []
        name_lower = package_name.lower()
        
        for pattern in self.suspicious_patterns:
            if re.match(pattern, name_lower):
                matched_patterns.append(pattern)
        
        return matched_patterns
    
    def analyze_name(self, package_name: str) -> Dict:
        """Analyze package name for various risk factors."""
        analysis = {
            "name": package_name,
            "typosquats": self.detect_typosquatting(package_name),
            "suspicious_patterns": self.check_suspicious_patterns(package_name),
            "length_risk": len(package_name) < 3 or len(package_name) > 50,
            "special_chars": bool(re.search(r'[^a-zA-Z0-9._-]', package_name)),
            "looks_like_version": bool(re.search(r'\d+\.\d+\.\d+', package_name)),
        }
        
        return analysis
    
    async def analyze_package(self, package_name: str) -> Dict:
        """Comprehensive package analysis."""
        # Start with name analysis
        name_analysis = self.analyze_name(package_name)
        
        # Check malicious database
        malicious_info = self.db.is_malicious(package_name)
        
        # Fetch PyPI metadata
        pypi_info = await self.db.fetch_pypi_info(package_name)
        
        # Check OSV for vulnerabilities
        osv_vulns = await self.db.check_osv_database(package_name)
        
        # Analyze PyPI metadata for suspicious indicators
        metadata_analysis = self._analyze_pypi_metadata(pypi_info) if pypi_info else {}
        
        return {
            "package_name": package_name,
            "name_analysis": name_analysis,
            "malicious_info": malicious_info,
            "pypi_info": pypi_info,
            "osv_vulnerabilities": osv_vulns,
            "metadata_analysis": metadata_analysis,
        }
    
    def _analyze_pypi_metadata(self, pypi_info: Dict) -> Dict:
        """Analyze PyPI metadata for suspicious indicators."""
        if not pypi_info:
            return {"exists": False}
        
        info = pypi_info.get("info", {})
        
        # Extract relevant metadata
        created = info.get("releases", {})
        if created:
            latest_release = max(created.values(), key=lambda x: x.get("upload_time", ""))
            upload_time = latest_release.get("upload_time", "")
        else:
            upload_time = ""
        
        summary = info.get("summary", "")
        description = info.get("description", "")
        
        # Risk indicators
        risk_indicators = {
            "exists": True,
            "very_new_package": self._is_very_recent(upload_time),
            "no_description": not summary.strip() and not description.strip(),
            "short_description": len(summary.strip()) < 20,
            "suspicious_description": self._has_suspicious_description(summary + " " + description),
            "low_download_count": self._has_low_downloads(info),
            "no_homepage": not info.get("home_page"),
            "no_github_repo": not self._has_github_repo(info),
            "many_maintainers": len(info.get("maintainers", [])) > 10,
        }
        
        return risk_indicators
    
    def _is_very_recent(self, upload_time: str) -> bool:
        """Check if package was uploaded very recently."""
        if not upload_time:
            return True
        
        try:
            from datetime import datetime, timedelta
            upload_date = datetime.fromisoformat(upload_time.replace('Z', '+00:00'))
            now = datetime.now(upload_date.tzinfo)
            return (now - upload_date) < timedelta(days=7)
        except:
            return True
    
    def _has_suspicious_description(self, text: str) -> bool:
        """Check for suspicious keywords in description."""
        suspicious_keywords = [
            "test", "demo", "example", "sample", "proof of concept",
            "educational", "research", "experiment", "placeholder"
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in suspicious_keywords)
    
    def _has_low_downloads(self, info: Dict) -> bool:
        """Check if package has suspiciously low download counts."""
        # This is a heuristic - many malicious packages have very few downloads
        try:
            # PyPI doesn't always provide download counts in API
            # This is a placeholder for future enhancement
            return False
        except:
            return False
    
    def _has_github_repo(self, info: Dict) -> bool:
        """Check if package has a GitHub repository."""
        project_urls = info.get("project_urls", {})
        homepage = info.get("home_page", "")
        
        # Check if any URL points to GitHub
        all_urls = [homepage] + list(project_urls.values())
        return any("github.com" in url for url in all_urls if url)
