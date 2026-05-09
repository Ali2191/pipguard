"""
Static code analysis module for PipGuard.
Analyzes package source code for suspicious patterns and malicious behavior.
"""

import ast
import re
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse

import httpx


class StaticCodeAnalyzer:
    """Analyzes Python package source code for security threats."""
    
    def __init__(self):
        self.suspicious_imports = {
            'crypto', 'cryptography', 'hashlib', 'secrets',
            'socket', 'subprocess', 'os', 'sys', 'platform',
            'urllib', 'requests', 'ftplib', 'smtplib',
            'webbrowser', 'tempfile', 'shutil', 'glob'
        }
        
        self.malicious_patterns = {
            'base64_encoded_strings': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hardcoded_urls': r'https?://[^\s\'"<>]+',
            'suspicious_comments': r'#.*(?:todo|fixme|hack|backdoor|malicious)',
            'obfuscated_code': r'exec\s*\(\s*["\'].*["\']\s*\)',
            'network_connections': r'socket\.(?:socket|connect|create_connection)',
            'file_operations': r'open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']w["\']',
            'system_commands': r'subprocess\.(?:call|run|Popen|check_output)',
            'crypto_operations': r'(?:hashlib|crypto|cryptography)\.\w+',
            'environment_access': r'os\.(?:environ|getenv|putenv|system)',
            'suspicious_encoding': r'eval\s*\(|exec\s*\(|compile\s*\(',
        }
        
        self.typosquat_indicators = [
            r'.*fake.*', r'.*scam.*', r'.*malware.*',
            r'.*backdoor.*', r'.*trojan.*', r'.*keylog.*'
        ]
    
    async def analyze_package_source(self, package_name: str, version: Optional[str] = None) -> Dict:
        """Download and analyze package source code."""
        try:
            # Get package download URL
            download_url = await self._get_package_download_url(package_name, version)
            if not download_url:
                return {"error": "Could not find package download URL"}
            
            # Download package
            with tempfile.TemporaryDirectory() as temp_dir:
                package_path = await self._download_package(download_url, temp_dir)
                
                # Analyze extracted package
                analysis_results = await self._analyze_package_files(package_path)
                
                return {
                    "package_name": package_name,
                    "version": version,
                    "download_url": download_url,
                    "analysis": analysis_results,
                    "risk_score": self._calculate_static_risk_score(analysis_results),
                    "suspicious_files": analysis_results.get("suspicious_files", []),
                    "security_issues": analysis_results.get("security_issues", [])
                }
                
        except Exception as e:
            return {"error": f"Failed to analyze package source: {str(e)}"}
    
    async def _get_package_download_url(self, package_name: str, version: Optional[str]) -> Optional[str]:
        """Get PyPI download URL for package."""
        try:
            async with httpx.AsyncClient() as client:
                # Get package info
                package_url = f"https://pypi.org/pypi/{package_name}/json"
                response = await client.get(package_url, timeout=10)
                
                if response.status_code != 200:
                    return None
                
                package_data = response.json()
                releases = package_data.get("releases", {})
                
                # Find appropriate version
                if version and version in releases:
                    release_info = releases[version]
                elif releases:
                    # Get latest version
                    latest_version = max(releases.keys())
                    release_info = releases[latest_version]
                else:
                    return None
                
                # Find wheel URL
                for file_info in release_info.get("files", []):
                    if file_info.get("packagetype") == "bdist_wheel":
                        return file_info.get("url")
                
                # Fallback to source URL
                for file_info in release_info.get("files", []):
                    if file_info.get("packagetype") == "sdist":
                        return file_info.get("url")
                
                return None
                
        except Exception as e:
            print(f"Error getting package URL: {e}")
            return None
    
    async def _download_package(self, url: str, temp_dir: str) -> Path:
        """Download and extract package."""
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=30)
            response.raise_for_status()
            
            # Save to temp file
            filename = Path(url).name
            package_path = Path(temp_dir) / filename
            
            with open(package_path, 'wb') as f:
                f.write(response.content)
            
            # Extract if it's an archive
            if filename.endswith(('.zip', '.tar.gz', '.tgz')):
                extract_dir = Path(temp_dir) / "extracted"
                extract_dir.mkdir(exist_ok=True)
                
                if filename.endswith('.zip'):
                    with zipfile.ZipFile(package_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                else:
                    import tarfile
                    with tarfile.open(package_path, 'r:*') as tar_ref:
                        tar_ref.extractall(extract_dir)
                
                return extract_dir
            
            return package_path
    
    async def _analyze_package_files(self, package_path: Path) -> Dict:
        """Analyze all files in the package."""
        results = {
            "files_analyzed": 0,
            "suspicious_files": [],
            "security_issues": [],
            "imports_analysis": {},
            "code_patterns": {},
            "metadata_analysis": {}
        }
        
        # Find Python files
        python_files = list(package_path.rglob("*.py"))
        setup_files = list(package_path.rglob("setup.py"))
        pyproject_files = list(package_path.rglob("pyproject.toml"))
        
        # Analyze setup files
        for setup_file in setup_files + pyproject_files:
            setup_analysis = self._analyze_setup_file(setup_file)
            results["metadata_analysis"][setup_file.name] = setup_analysis
        
        # Analyze Python source files
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                file_analysis = self._analyze_python_file(content, py_file.name)
                results["files_analyzed"] += 1
                
                # Check if file is suspicious
                if file_analysis["risk_score"] > 50:
                    results["suspicious_files"].append({
                        "file": str(py_file.relative_to(package_path)),
                        "risk_score": file_analysis["risk_score"],
                        "issues": file_analysis["issues"]
                    })
                
                # Collect security issues
                results["security_issues"].extend(file_analysis["security_issues"])
                
                # Aggregate imports analysis
                for imp, count in file_analysis["imports"].items():
                    if imp in results["imports_analysis"]:
                        results["imports_analysis"][imp] += count
                    else:
                        results["imports_analysis"][imp] = count
                
                # Aggregate pattern matches
                for pattern, matches in file_analysis["patterns"].items():
                    if pattern in results["code_patterns"]:
                        results["code_patterns"][pattern] += len(matches)
                    else:
                        results["code_patterns"][pattern] = len(matches)
                        
            except Exception as e:
                print(f"Error analyzing {py_file}: {e}")
        
        return results
    
    def _analyze_setup_file(self, setup_file: Path) -> Dict:
        """Analyze setup.py or pyproject.toml for suspicious metadata."""
        try:
            content = setup_file.read_text(encoding='utf-8', errors='ignore')
            
            analysis = {
                "suspicious_urls": [],
                "suspicious_dependencies": [],
                "obfuscated_info": False,
                "risk_indicators": []
            }
            
            # Check for suspicious URLs
            url_pattern = r'https?://[^\s\'"<>]+'
            urls = re.findall(url_pattern, content)
            
            for url in urls:
                parsed = urlparse(url)
                if any(suspicious in parsed.netloc.lower() for suspicious in [
                    'bit.ly', 'tinyurl.com', 'pastebin.com', 'github.com/gist',
                    'discord.com', 'telegram.org', 't.me'
                ]):
                    analysis["suspicious_urls"].append(url)
                    analysis["risk_indicators"].append("Suspicious URL in setup")
            
            # Check for obfuscated maintainer info
            if re.search(r'[\"\'][^\"\']*\\x[0-9a-fA-F][^\"\']*[\"\']', content):
                analysis["obfuscated_info"] = True
                analysis["risk_indicators"].append("Obfuscated maintainer information")
            
            # Check for suspicious dependencies
            deps_pattern = r'(?:install_requires|dependencies|extras_require)\s*=\s*\[([^\]]+)\]'
            deps_match = re.search(deps_pattern, content)
            
            if deps_match:
                deps_content = deps_match.group(1)
                for dep in re.findall(r'[\"\']([^\"\']+)[\"\']', deps_content):
                    for indicator in self.typosquat_indicators:
                        if re.search(indicator, dep, re.IGNORECASE):
                            analysis["suspicious_dependencies"].append(dep)
                            analysis["risk_indicators"].append(f"Suspicious dependency: {dep}")
            
            return analysis
            
        except Exception as e:
            return {"error": f"Failed to analyze setup file: {str(e)}"}
    
    def _analyze_python_file(self, content: str, filename: str) -> Dict:
        """Analyze a single Python file for security issues."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # Fall back to regex analysis for files with syntax errors
            return self._analyze_with_regex(content, filename)
        
        analysis = {
            "imports": {},
            "security_issues": [],
            "patterns": {},
            "risk_score": 0,
            "issues": []
        }
        
        # Analyze AST
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    import_name = alias.name if isinstance(alias, ast.alias) else alias
                    if import_name in self.suspicious_imports:
                        analysis["imports"][import_name] = analysis["imports"].get(import_name, 0) + 1
                        analysis["security_issues"].append(f"Suspicious import: {import_name}")
            
            elif isinstance(node, ast.ImportFrom):
                module_name = node.module
                if module_name and module_name in self.suspicious_imports:
                    analysis["imports"][module_name] = analysis["imports"].get(module_name, 0) + 1
                    analysis["security_issues"].append(f"Suspicious import: {module_name}")
            
            elif isinstance(node, ast.Call):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    
                    if func_name in ['eval', 'exec', 'compile', '__import__']:
                        analysis["security_issues"].append(f"Dangerous function call: {func_name}")
                        analysis["risk_score"] += 20
                    
                    elif func_name in ['open', 'file', 'write_file']:
                        # Check if opening in write mode
                        for keyword in node.keywords:
                            if keyword.arg == 'mode' and 'w' in str(keyword.value):
                                analysis["security_issues"].append("File opened in write mode")
                                analysis["risk_score"] += 15
            
            elif isinstance(node, ast.FunctionDef):
                # Check for obfuscated function names
                if re.search(r'[a-zA-Z]*_[a-zA-Z]*_[a-zA-Z]*', node.name):
                    analysis["security_issues"].append(f"Obfuscated function name: {node.name}")
                    analysis["risk_score"] += 10
        
        # Pattern analysis with regex
        for pattern_name, pattern in self.malicious_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis["patterns"][pattern_name] = matches
                
                # Add risk score based on pattern type
                risk_scores = {
                    'base64_encoded_strings': 15,
                    'hardcoded_urls': 10,
                    'suspicious_comments': 20,
                    'obfuscated_code': 25,
                    'network_connections': 15,
                    'file_operations': 10,
                    'system_commands': 20,
                    'crypto_operations': 15,
                    'environment_access': 10,
                    'suspicious_encoding': 30
                }
                
                analysis["risk_score"] += risk_scores.get(pattern_name, 5) * len(matches)
        
        analysis["issues"] = analysis["security_issues"]
        return analysis
    
    def _analyze_with_regex(self, content: str, filename: str) -> Dict:
        """Fallback analysis using regex when AST parsing fails."""
        analysis = {
            "imports": {},
            "security_issues": [],
            "patterns": {},
            "risk_score": 0,
            "issues": []
        }
        
        # Simple regex-based import detection
        import_pattern = r'(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\s+as\s+([a-zA-Z_][a-zA-Z0-9_]*))?'
        imports = re.findall(import_pattern, content)
        
        for import_match in imports:
            module_name = import_match[1]
            if module_name in self.suspicious_imports:
                analysis["imports"][module_name] = analysis["imports"].get(module_name, 0) + 1
                analysis["security_issues"].append(f"Suspicious import: {module_name}")
        
        # Pattern analysis
        for pattern_name, pattern in self.malicious_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis["patterns"][pattern_name] = matches
                analysis["risk_score"] += 10 * len(matches)
        
        analysis["issues"] = analysis["security_issues"]
        return analysis
    
    def _calculate_static_risk_score(self, analysis_results: Dict) -> int:
        """Calculate overall risk score from static analysis."""
        score = 0
        
        # Base score from suspicious files
        suspicious_files = analysis_results.get("suspicious_files", [])
        score += len(suspicious_files) * 25
        
        # Score from security issues
        security_issues = analysis_results.get("security_issues", [])
        score += len(security_issues) * 10
        
        # Score from suspicious patterns
        code_patterns = analysis_results.get("code_patterns", {})
        pattern_scores = {
            'base64_encoded_strings': 5,
            'hardcoded_urls': 8,
            'suspicious_comments': 15,
            'obfuscated_code': 20,
            'network_connections': 12,
            'file_operations': 8,
            'system_commands': 15,
            'crypto_operations': 12,
            'environment_access': 8,
            'suspicious_encoding': 25
        }
        
        for pattern, count in code_patterns.items():
            score += pattern_scores.get(pattern, 5) * count
        
        # Score from metadata issues
        metadata_analysis = analysis_results.get("metadata_analysis", {})
        for file_analysis in metadata_analysis.values():
            if isinstance(file_analysis, dict):
                risk_indicators = file_analysis.get("risk_indicators", [])
                score += len(risk_indicators) * 10
        
        return min(score, 100)  # Cap at 100
