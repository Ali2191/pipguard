"""
Dependency graph analysis module for PipGuard.
Analyzes package dependencies for transitive attacks and supply chain risks.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass

import httpx
from .database import MaliciousPackageDB
from .analyzer import PackageAnalyzer


@dataclass
class DependencyNode:
    """Represents a package in the dependency graph."""
    name: str
    version: Optional[str] = None
    dependencies: List[str] = None
    risk_level: Optional[str] = None
    risk_score: int = 0
    depth: int = 0
    is_malicious: bool = False
    is_typosquat: bool = False
    download_count: int = 0
    last_updated: Optional[str] = None


class DependencyGraphAnalyzer:
    """Analyzes dependency graphs for supply chain security risks."""
    
    def __init__(self, db: MaliciousPackageDB):
        self.db = db
        self.analyzer = PackageAnalyzer(db)
        self.dependency_cache = {}
        self.py_api_cache = {}
    
    async def build_dependency_graph(self, package_name: str, max_depth: int = 3) -> Dict:
        """Build dependency graph for a package."""
        if package_name in self.dependency_cache:
            return self.dependency_cache[package_name]
        
        graph = {
            "root": package_name,
            "nodes": {},
            "edges": [],
            "risk_analysis": {}
        }
        
        # Build graph recursively
        root_node = await self._build_node(package_name, 0, max_depth, graph)
        graph["nodes"][package_name] = root_node
        
        # Analyze graph for security risks
        await self._analyze_graph_security(graph)
        
        # Cache result
        self.dependency_cache[package_name] = graph
        
        return graph
    
    async def _build_node(self, package_name: str, depth: int, max_depth: int, graph: Dict) -> DependencyNode:
        """Build a single node in the dependency graph."""
        if depth >= max_depth:
            return DependencyNode(name=package_name, depth=depth)
        
        # Get package info from PyPI
        pypi_info = await self._get_pypi_info(package_name)
        if not pypi_info:
            return DependencyNode(name=package_name, depth=depth, download_count=0)
        
        # Extract dependencies
        dependencies = self._extract_dependencies(pypi_info)
        
        # Check if package is malicious or typosquat
        analysis = await self.analyzer.analyze_package(package_name)
        risk_analysis = self.analyzer.risk_scorer.calculate_risk_score(analysis)
        
        # Create node
        node = DependencyNode(
            name=package_name,
            version=pypi_info.get("version"),
            dependencies=dependencies,
            risk_level=risk_analysis["level"],
            risk_score=risk_analysis["score"],
            depth=depth,
            is_malicious=analysis.get("malicious_info") is not None,
            is_typosquat=len(analysis.get("typosquats", [])) > 0,
            download_count=pypi_info.get("downloads", 0),
            last_updated=pypi_info.get("upload_time")
        )
        
        # Build child nodes recursively
        for dep in dependencies[:10]:  # Limit to 10 dependencies per node
            if dep not in graph["nodes"]:
                child_node = await self._build_node(dep, depth + 1, max_depth, graph)
                graph["nodes"][dep] = child_node
                
                # Add edge
                graph["edges"].append({
                    "from": package_name,
                    "to": dep,
                    "type": "dependency"
                })
        
        return node
    
    async def _get_pypi_info(self, package_name: str) -> Optional[Dict]:
        """Get package information from PyPI API."""
        if package_name in self.py_api_cache:
            return self.py_api_cache[package_name]
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://pypi.org/pypi/{package_name}/json",
                    timeout=10
                )
                
                if response.status_code != 200:
                    return None
                
                data = response.json()
                
                # Extract relevant info
                info = {
                    "name": data.get("info", {}).get("name", package_name),
                    "version": data.get("info", {}).get("version"),
                    "description": data.get("info", {}).get("description", ""),
                    "author": data.get("info", {}).get("author", ""),
                    "maintainers": data.get("info", {}).get("maintainers", []),
                    "license": data.get("info", {}).get("license", ""),
                    "keywords": data.get("info", {}).get("keywords", []),
                    "classifiers": data.get("info", {}).get("classifiers", []),
                    "requires_dist": data.get("info", {}).get("requires_dist", []),
                    "upload_time": data.get("info", {}).get("upload_time"),
                    "downloads": self._get_download_count(data)
                }
                
                # Cache result
                self.py_api_cache[package_name] = info
                
                return info
                
        except Exception as e:
            print(f"Error getting PyPI info for {package_name}: {e}")
            return None
    
    def _get_download_count(self, pypi_data: Dict) -> int:
        """Extract download count from PyPI data."""
        try:
            # Try different fields for download count
            info = pypi_data.get("info", {})
            
            # Check for direct download count
            if "downloads" in info:
                return info["downloads"]
            
            # Check for daily downloads
            if "daily_downloads" in info:
                return info["daily_downloads"]
            
            # Check for weekly downloads
            if "weekly_downloads" in info:
                return info["weekly_downloads"]
            
            # Check for monthly downloads
            if "monthly_downloads" in info:
                return info["monthly_downloads"]
            
            # Check in releases
            releases = pypi_data.get("releases", {})
            if releases:
                total_downloads = 0
                for release in releases.values():
                    if isinstance(release, dict):
                        total_downloads += release.get("downloads", 0)
                
                if total_downloads > 0:
                    return total_downloads
            
            return 0
            
        except Exception:
            return 0
    
    def _extract_dependencies(self, pypi_info: Dict) -> List[str]:
        """Extract dependency list from PyPI info."""
        dependencies = []
        
        # Check requires_dist
        requires_dist = pypi_info.get("requires_dist", [])
        for req in requires_dist:
            if isinstance(req, dict) and "requires" in req:
                for dep in req["requires"]:
                    if isinstance(dep, dict):
                        dependencies.append(dep.get("project_name", ""))
                    elif isinstance(dep, str):
                        dependencies.append(dep)
        
        # Check install_requires
        info = pypi_info.get("info", {})
        if "install_requires" in info:
            install_requires = info["install_requires"]
            if isinstance(install_requires, list):
                for req in install_requires:
                    # Parse requirement string
                    dep_name = req.split(">=")[0].split("<")[0].split(">=")[0].strip()
                    if dep_name:
                        dependencies.append(dep_name)
        
        # Remove duplicates and empty strings
        dependencies = list(set(filter(None, dependencies)))
        return dependencies
    
    async def _analyze_graph_security(self, graph: Dict):
        """Analyze dependency graph for security risks."""
        risk_analysis = {
            "total_packages": len(graph["nodes"]),
            "max_depth": 0,
            "malicious_packages": [],
            "typosquat_packages": [],
            "suspicious_patterns": [],
            "supply_chain_risks": [],
            "dependency_risk_score": 0
        }
        
        # Find maximum depth
        for node in graph["nodes"].values():
            risk_analysis["max_depth"] = max(risk_analysis["max_depth"], node.depth)
        
        # Identify malicious packages
        for name, node in graph["nodes"].items():
            if node.is_malicious:
                risk_analysis["malicious_packages"].append({
                    "name": name,
                    "depth": node.depth,
                    "risk_score": node.risk_score
                })
            
            if node.is_typosquat:
                risk_analysis["typosquat_packages"].append({
                    "name": name,
                    "depth": node.depth,
                    "target_package": node.name  # This would be the original package
                })
        
        # Analyze suspicious patterns
        for name, node in graph["nodes"].items():
            if self._has_suspicious_pattern(name):
                risk_analysis["suspicious_patterns"].append({
                    "name": name,
                    "depth": node.depth,
                    "risk_score": node.risk_score
                })
        
        # Calculate supply chain risks
        supply_chain_risks = await self._calculate_supply_chain_risks(graph)
        risk_analysis["supply_chain_risks"] = supply_chain_risks
        
        # Calculate overall dependency risk score
        risk_analysis["dependency_risk_score"] = self._calculate_dependency_risk_score(graph)
        
        # Store analysis in graph
        graph["risk_analysis"] = risk_analysis
    
    def _has_suspicious_pattern(self, package_name: str) -> bool:
        """Check if package name matches suspicious patterns."""
        suspicious_patterns = [
            r'^[a-z]*crypto[a-z]*$',
            r'^[a-z]*miner[a-z]*$',
            r'^[a-z]*hack[a-z]*$',
            r'^[a-z]*crack[a-z]*$',
            r'^[a-z]*steal[a-z]*$',
            r'^[a-z]*keylog[a-z]*$',
            r'^[a-z]*backdoor[a-z]*$',
            r'^[a-z]*rat[a-z]*$',
            r'^[a-z]*trojan[a-z]*$',
            r'^[a-z]*malware[a-z]*$'
        ]
        
        import re
        return any(re.search(pattern, package_name, re.IGNORECASE) for pattern in suspicious_patterns)
    
    async def _calculate_supply_chain_risks(self, graph: Dict) -> List[Dict]:
        """Calculate supply chain security risks."""
        risks = []
        
        # Risk 1: Deep dependency chains
        for name, node in graph["nodes"].items():
            if node.depth >= 3:
                risks.append({
                    "type": "deep_dependency_chain",
                    "package": name,
                    "depth": node.depth,
                    "description": f"Package is {node.depth} levels deep in dependency chain",
                    "severity": "medium"
                })
        
        # Risk 2: Many dependencies from single package
        for name, node in graph["nodes"].items():
            if node.dependencies and len(node.dependencies) > 20:
                risks.append({
                    "type": "excessive_dependencies",
                    "package": name,
                    "dependency_count": len(node.dependencies),
                    "description": f"Package has {len(node.dependencies)} dependencies",
                    "severity": "low"
                })
        
        # Risk 3: Unknown or suspicious maintainers
        for name, node in graph["nodes"].items():
            if node.download_count < 100 and node.depth <= 1:
                risks.append({
                    "type": "unpopular_package",
                    "package": name,
                    "download_count": node.download_count,
                    "description": f"Package has only {node.download_count} downloads",
                    "severity": "medium"
                })
        
        # Risk 4: Recently uploaded packages
        for name, node in graph["nodes"].items():
            if node.last_updated:
                try:
                    from datetime import datetime, timezone
                    upload_date = datetime.fromisoformat(node.last_updated.replace('Z', '+00:00'))
                    days_old = (datetime.now(timezone.utc) - upload_date).days
                    
                    if days_old < 7:
                        risks.append({
                            "type": "very_new_package",
                            "package": name,
                            "days_old": days_old,
                            "description": f"Package uploaded only {days_old} days ago",
                            "severity": "high"
                        })
                except:
                    pass
        
        return risks
    
    def _calculate_dependency_risk_score(self, graph: Dict) -> int:
        """Calculate overall risk score for dependency graph."""
        total_score = 0
        
        for name, node in graph["nodes"].items():
            # Base score from node risk
            node_score = node.risk_score
            
            # Depth multiplier (deeper = more risk)
            depth_multiplier = 1 + (node.depth * 0.2)
            
            # Dependency count multiplier
            dep_multiplier = 1
            if node.dependencies:
                dep_count = len(node.dependencies)
                if dep_count > 10:
                    dep_multiplier = 1.5
                elif dep_count > 5:
                    dep_multiplier = 1.2
            
            # Popularity multiplier (inverse)
            popularity_multiplier = 1.0
            if node.download_count > 10000:
                popularity_multiplier = 0.8
            elif node.download_count > 1000:
                popularity_multiplier = 0.9
            elif node.download_count < 100:
                popularity_multiplier = 1.3
            
            # Calculate final score
            final_score = node_score * depth_multiplier * dep_multiplier * popularity_multiplier
            total_score += final_score
        
        return min(int(total_score), 100)
    
    async def get_transitive_risks(self, package_name: str) -> Dict:
        """Get transitive security risks for a package."""
        graph = await self.build_dependency_graph(package_name)
        
        return {
            "package": package_name,
            "transitive_risks": graph["risk_analysis"]["supply_chain_risks"],
            "dependency_risk_score": graph["risk_analysis"]["dependency_risk_score"],
            "total_dependencies": len(graph["nodes"]),
            "max_depth": graph["risk_analysis"]["max_depth"],
            "malicious_in_chain": graph["risk_analysis"]["malicious_packages"],
            "typosquats_in_chain": graph["risk_analysis"]["typosquat_packages"]
        }
    
    def export_graph(self, graph: Dict, format: str = "json") -> str:
        """Export dependency graph in specified format."""
        if format == "json":
            return json.dumps(graph, indent=2)
        
        elif format == "dot":
            # GraphViz DOT format
            lines = ["digraph dependencies {"]
            
            for edge in graph["edges"]:
                lines.append(f'  "{edge["from"]}" -> "{edge["to"]}";')
            
            lines.append("}")
            return "\n".join(lines)
        
        elif format == "mermaid":
            # Mermaid format
            lines = ["graph TD"]
            
            for edge in graph["edges"]:
                lines.append(f'  {edge["from"]} --> {edge["to"]}')
            
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
