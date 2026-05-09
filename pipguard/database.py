"""
Malicious package database management for PipGuard.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
import requests
import httpx


class MaliciousPackageDB:
    """Database for tracking malicious and suspicious packages."""
    
    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the malicious package database."""
        if db_path is None:
            db_path = Path.home() / ".pipguard" / "malicious.db"
        
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        
        # Cache for API responses
        self._cache = {}
        self._cache_ttl = 3600  # 1 hour
        
    def _init_database(self):
        """Initialize SQLite database with required tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS malicious_packages (
                    name TEXT PRIMARY KEY,
                    reason TEXT,
                    source TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    risk_level TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS package_cache (
                    name TEXT PRIMARY KEY,
                    data TEXT,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    
    def add_malicious_package(self, name: str, reason: str, source: str, risk_level: str = "HIGH"):
        """Add a malicious package to the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO malicious_packages (name, reason, source, risk_level) VALUES (?, ?, ?, ?)",
                (name.lower(), reason, source, risk_level)
            )
            conn.commit()
    
    def is_malicious(self, package_name: str) -> Optional[Dict]:
        """Check if a package is in the malicious database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM malicious_packages WHERE name = ?",
                (package_name.lower(),)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "name": row["name"],
                    "reason": row["reason"], 
                    "source": row["source"],
                    "risk_level": row["risk_level"],
                    "added_at": row["added_at"]
                }
        return None
    
    def load_initial_data(self):
        """Load initial malicious package data from OSV and other sources."""
        # Known malicious packages from recent incidents
        initial_packages = [
            ("reqeusts", "Typosquat of 'requests' package", "manual", "HIGH"),
            ("urlib3", "Typosquat of 'urllib3' package", "manual", "HIGH"),
            ("fake-crypto", "Suspicious crypto package name", "manual", "MEDIUM"),
            ("pytorch-lightning", "Compromised package name", "manual", "HIGH"),
            ("chat-gpt-api", "Fake ChatGPT package", "manual", "HIGH"),
            ("openai-gpt", "Fake OpenAI package", "manual", "MEDIUM"),
        ]
        
        for name, reason, source, risk_level in initial_packages:
            self.add_malicious_package(name, reason, source, risk_level)
    
    async def fetch_pypi_info(self, package_name: str) -> Optional[Dict]:
        """Fetch package information from PyPI API."""
        # Check cache first
        cache_key = f"pypi_{package_name}"
        if cache_key in self._cache:
            cached_data, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return cached_data
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    self._cache[cache_key] = (data, time.time())
                    return data
        except Exception as e:
            print(f"Warning: Could not fetch PyPI info for {package_name}: {e}")
        
        return None
    
    async def check_osv_database(self, package_name: str) -> List[Dict]:
        """Check OSV database for package vulnerabilities."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://api.osv.dev/v1/query?package={package_name}&ecosystem=PyPI",
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("vulns", [])
        except Exception as e:
            print(f"Warning: Could not check OSV database for {package_name}: {e}")
        
        return []
    
    async def update_malicious_database(self) -> int:
        """Update malicious package database from external sources."""
        updated_count = 0
        
        # Fetch from OpenSSF malicious packages
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/repos/ossf/malicious-packages/contents/py",
                    timeout=30
                )
                if response.status_code == 200:
                    data = response.json()
                    for file_info in data:
                        if file_info["name"].endswith(".json"):
                            file_response = await client.get(file_info["download_url"])
                            if file_response.status_code == 200:
                                import base64
                                import json
                                content = base64.b64decode(file_response.json()["content"]).decode()
                                malicious_data = json.loads(content)
                                
                                for package in malicious_data:
                                    self.add_malicious_package(
                                        package["name"],
                                        package.get("summary", "External malicious package"),
                                        "OpenSSF",
                                        "HIGH"
                                    )
                                    updated_count += 1
        except Exception as e:
            print(f"Warning: Could not update from OpenSSF: {e}")
        
        # Fetch from PyPA advisory database
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/",
                    timeout=30
                )
                if response.status_code == 200:
                    # Parse directory listing (simplified)
                    import re
                    package_names = re.findall(r'href="([^"]*\.json)"', response.text)
                    for package_name in package_names:
                        if package_name.endswith('.json'):
                            pkg_name = package_name[:-5]  # Remove .json
                            pkg_response = await client.get(
                                f"https://raw.githubusercontent.com/pypa/advisory-database/main/vulns/{package_name}"
                            )
                            if pkg_response.status_code == 200:
                                advisory_data = pkg_response.json()
                                for advisory in advisory_data:
                                    self.add_malicious_package(
                                        advisory.get("name", pkg_name),
                                        advisory.get("summary", "PyPA advisory"),
                                        "PyPA",
                                        "HIGH"
                                    )
                                    updated_count += 1
        except Exception as e:
            print(f"Warning: Could not update from PyPA: {e}")
        
        return updated_count
