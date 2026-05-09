"""
Risk scoring system for PipGuard package analysis.
"""

from typing import Dict, List
from datetime import datetime, timedelta


class RiskScorer:
    """Calculates risk scores for packages based on various factors."""
    
    def __init__(self):
        """Initialize risk scorer with weighting factors."""
        self.weights = {
            "known_malicious": 100,    # Highest priority
            "typosquat_high": 80,        # Very high similarity to popular package
            "typosquat_medium": 60,       # Medium similarity
            "suspicious_pattern": 50,       # Matches suspicious regex patterns
            "very_new": 30,               # Package uploaded < 7 days ago
            "no_metadata": 25,             # Missing description/homepage
            "low_quality": 20,              # Short description, no repo
            "vulnerability": 40,             # Known vulnerabilities
        }
    
    def calculate_risk_score(self, analysis: Dict) -> Dict:
        """Calculate overall risk score and level."""
        score = 0
        reasons = []
        
        # Check if package is known malicious
        if analysis.get("malicious_info"):
            score += self.weights["known_malicious"]
            reasons.append(f"Known malicious package: {analysis['malicious_info']['reason']}")
        
        # Check typosquatting
        typosquats = analysis.get("name_analysis", {}).get("typosquats", [])
        if typosquats:
            similarity = typosquats[0][1]  # Highest similarity
            if similarity > 0.9:
                score += self.weights["typosquat_high"]
                reasons.append(f"High similarity typosquat of '{typosquats[0][0]}' ({similarity:.0%})")
            elif similarity > 0.8:
                score += self.weights["typosquat_medium"] 
                reasons.append(f"Medium similarity typosquat of '{typosquats[0][0]}' ({similarity:.0%})")
        
        # Check suspicious patterns
        suspicious_patterns = analysis.get("name_analysis", {}).get("suspicious_patterns", [])
        if suspicious_patterns:
            score += self.weights["suspicious_pattern"]
            reasons.append(f"Matches suspicious patterns: {', '.join(suspicious_patterns)}")
        
        # Check metadata risk factors
        metadata = analysis.get("metadata_analysis", {})
        if metadata:
            if metadata.get("very_new_package"):
                score += self.weights["very_new"]
                reasons.append("Package uploaded very recently (< 7 days)")
            
            if metadata.get("no_description") or metadata.get("short_description"):
                score += self.weights["no_metadata"]
                reasons.append("Missing or very short description")
            
            if metadata.get("suspicious_description"):
                score += self.weights["low_quality"]
                reasons.append("Suspicious keywords in description")
            
            if metadata.get("low_download_count"):
                score += self.weights["low_quality"]
                reasons.append("Suspiciously low download activity")
            
            if not metadata.get("no_homepage") and not metadata.get("no_github_repo"):
                score += self.weights["no_metadata"]
                reasons.append("No homepage or GitHub repository")
        
        # Check for vulnerabilities
        vulns = analysis.get("osv_vulnerabilities", [])
        if vulns:
            score += self.weights["vulnerability"] * len(vulns)
            reasons.append(f"Has {len(vulns)} known vulnerabilities")
        
        # Determine risk level
        risk_level = self._get_risk_level(score)
        
        return {
            "score": score,
            "level": risk_level,
            "reasons": reasons,
            "recommendation": self._get_recommendation(risk_level)
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 15:
            return "LOW"
        else:
            return "SAFE"
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            "HIGH": "⚠️  DO NOT INSTALL - This package shows strong indicators of being malicious",
            "MEDIUM": "⚠️  Exercise caution - Review package details before installing", 
            "LOW": "ℹ️  Minor concerns - Package appears safe but has some risk factors",
            "SAFE": "✅  No significant risks detected"
        }
        return recommendations.get(risk_level, "ℹ️  Risk level unknown")
