"""
PipGuard API Server - REST API for external tool integration
Provides endpoints for package security analysis and team collaboration.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl

from .database import MaliciousPackageDB
from .analyzer import PackageAnalyzer
from .risk_scorer import RiskScorer


class PackageAnalysisRequest(BaseModel):
    package_name: str
    version: Optional[str] = None
    include_dependencies: bool = False


class PackageAnalysisResponse(BaseModel):
    package_name: str
    risk_level: str
    risk_score: int
    reasons: List[str]
    analysis_timestamp: datetime
    recommendations: List[str]


class BulkAnalysisRequest(BaseModel):
    packages: List[str]
    analysis_type: str = "basic"  # basic, full, dependencies


class TeamPolicy(BaseModel):
    name: str
    blocked_packages: List[str] = []
    allowed_packages: List[str] = []
    minimum_risk_level: str = "MEDIUM"
    auto_block_high_risk: bool = False


app = FastAPI(
    title="PipGuard API",
    description="REST API for Python package security analysis",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
db = MaliciousPackageDB()
analyzer = PackageAnalyzer(db)
scorer = RiskScorer()


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    db.load_initial_data()


@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "message": "PipGuard Security API",
        "version": "0.1.0",
        "endpoints": {
            "analyze": "/analyze",
            "bulk_analyze": "/analyze/bulk",
            "health": "/health",
            "stats": "/stats"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow()}


@app.post("/analyze", response_model=PackageAnalysisResponse)
async def analyze_package(request: PackageAnalysisRequest):
    """Analyze a single package for security risks."""
    try:
        # Perform analysis
        analysis = await analyzer.analyze_package(request.package_name)
        risk_analysis = scorer.calculate_risk_score(analysis)
        
        # Generate recommendations
        recommendations = []
        if risk_analysis["level"] == "HIGH":
            recommendations.append("DO NOT INSTALL - This package shows strong indicators of being malicious")
            recommendations.append("Consider using the legitimate package instead")
        elif risk_analysis["level"] == "MEDIUM":
            recommendations.append("Exercise caution - Review package source and maintainers")
            recommendations.append("Consider alternatives with better reputation")
        elif risk_analysis["level"] == "LOW":
            recommendations.append("Minor concerns - Package appears safe but has some risk factors")
            recommendations.append("Review package documentation and recent activity")
        else:
            recommendations.append("Package appears safe for installation")
        
        return PackageAnalysisResponse(
            package_name=request.package_name,
            risk_level=risk_analysis["level"],
            risk_score=risk_analysis["score"],
            reasons=risk_analysis["reasons"],
            analysis_timestamp=datetime.utcnow(),
            recommendations=recommendations
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/analyze/bulk")
async def analyze_packages_bulk(request: BulkAnalysisRequest):
    """Analyze multiple packages in bulk."""
    try:
        results = []
        
        for package_name in request.packages:
            analysis = await analyzer.analyze_package(package_name)
            risk_analysis = scorer.calculate_risk_score(analysis)
            
            results.append({
                "package_name": package_name,
                "risk_level": risk_analysis["level"],
                "risk_score": risk_analysis["score"],
                "reasons": risk_analysis["reasons"]
            })
        
        return {"results": results, "total_analyzed": len(results)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")


@app.get("/stats")
async def get_statistics():
    """Get API usage and database statistics."""
    return {
        "database_stats": {
            "malicious_packages_count": len(db.malicious_packages),
            "popular_packages_count": len(analyzer.popular_packages),
            "last_updated": datetime.utcnow().isoformat()
        },
        "api_info": {
            "version": "0.1.0",
            "endpoints": ["/analyze", "/analyze/bulk", "/health", "/stats"]
        }
    }


@app.post("/webhook/analyze")
async def webhook_analysis(background_tasks: BackgroundTasks, webhook_data: Dict):
    """Webhook endpoint for CI/CD integration."""
    try:
        # Extract packages from webhook payload
        packages = []
        
        if "packages" in webhook_data:
            packages = webhook_data["packages"]
        elif "requirements" in webhook_data:
            # Parse requirements.txt content
            content = webhook_data["requirements"]
            for line in content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    package = line.split('==')[0].split('>=')[0].strip()
                    if package:
                        packages.append(package)
        
        # Perform analysis in background
        background_tasks.add_task(
            perform_background_analysis,
            packages,
            webhook_data.get("callback_url"),
            webhook_data.get("project_name", "unknown")
        )
        
        return {"status": "accepted", "packages_to_analyze": len(packages)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Webhook processing failed: {str(e)}")


async def perform_background_analysis(
    packages: List[str], 
    callback_url: Optional[str], 
    project_name: str
):
    """Perform background analysis and send results via webhook."""
    try:
        results = []
        
        for package_name in packages:
            analysis = await analyzer.analyze_package(package_name)
            risk_analysis = scorer.calculate_risk_score(analysis)
            
            results.append({
                "package_name": package_name,
                "risk_level": risk_analysis["level"],
                "risk_score": risk_analysis["score"],
                "reasons": risk_analysis["reasons"],
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Send results via webhook if callback URL provided
        if callback_url:
            import httpx
            async with httpx.AsyncClient() as client:
                await client.post(
                    callback_url,
                    json={
                        "project_name": project_name,
                        "analysis_results": results,
                        "total_packages": len(results)
                    },
                    timeout=30
                )
        
    except Exception as e:
        print(f"Background analysis failed: {e}")


@app.get("/docs")
async def get_api_documentation():
    """Return API documentation as JSON."""
    return {
        "title": "PipGuard Security API",
        "description": "REST API for Python package security analysis",
        "version": "0.1.0",
        "endpoints": {
            "GET /": "API information and available endpoints",
            "GET /health": "Health check endpoint",
            "POST /analyze": "Analyze single package for security risks",
            "POST /analyze/bulk": "Analyze multiple packages in bulk",
            "GET /stats": "Get database and API statistics",
            "POST /webhook/analyze": "Webhook endpoint for CI/CD integration"
        },
        "examples": {
            "single_analysis": {
                "endpoint": "/analyze",
                "method": "POST",
                "body": {
                    "package_name": "requests",
                    "version": "2.28.0",
                    "include_dependencies": False
                }
            },
            "bulk_analysis": {
                "endpoint": "/analyze/bulk",
                "method": "POST", 
                "body": {
                    "packages": ["requests", "numpy", "pandas"],
                    "analysis_type": "basic"
                }
            },
            "webhook": {
                "endpoint": "/webhook/analyze",
                "method": "POST",
                "body": {
                    "packages": ["requests", "numpy"],
                    "callback_url": "https://your-ci-system.com/webhook",
                    "project_name": "my-project"
                }
            }
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
