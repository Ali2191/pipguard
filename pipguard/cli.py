"""
Command-line interface for PipGuard.
"""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
from rich.text import Text

from .database import MaliciousPackageDB
from .analyzer import PackageAnalyzer
from .risk_scorer import RiskScorer
from .config import ConfigManager


app = typer.Typer(
    help="PipGuard - Prevent accidental installation of malicious AI-generated packages",
    no_args_is_help=True,
    rich_markup_mode="rich"
)

console = Console()


def format_risk_warning(package_name: str, risk_analysis: dict) -> Panel:
    """Format risk warning as a rich panel."""
    risk_level = risk_analysis["level"]
    score = risk_analysis["score"]
    reasons = risk_analysis["reasons"]
    
    # Color coding for risk levels
    colors = {
        "HIGH": "red",
        "MEDIUM": "yellow", 
        "LOW": "blue",
        "SAFE": "green"
    }
    
    color = colors.get(risk_level, "white")
    
    # Create warning text
    warning_text = Text()
    warning_text.append(f"⚠️  Suspicious package detected: ", style="bold red")
    warning_text.append(f'"{package_name}"', style=f"bold {color}")
    warning_text.append(f"\n\nRisk Level: ", style="bold")
    warning_text.append(risk_level, style=f"bold {color}")
    warning_text.append(f" (Score: {score})")
    
    warning_text.append(f"\n\nReasons:\n")
    for i, reason in enumerate(reasons, 1):
        warning_text.append(f"{i}. {reason}\n")
    
    warning_text.append(f"\n{risk_analysis['recommendation']}")
    
    return Panel(
        warning_text,
        title="[bold red]PipGuard Security Alert[/bold red]",
        border_style=color,
        padding=(1, 2)
    )


@app.command()
def install(
    package_name: str = typer.Argument(..., help="Package name to install"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip security checks"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed analysis")
):
    """Install a package with security checks."""
    
    async def run_install():
        # Initialize components
        db = MaliciousPackageDB()
        db.load_initial_data()
        analyzer = PackageAnalyzer(db)
        scorer = RiskScorer()
        
        console.print(f"🔍 Analyzing package: {package_name}")
        
        # Analyze package
        analysis = await analyzer.analyze_package(package_name)
        risk_analysis = scorer.calculate_risk_score(analysis)
        
        if verbose:
            _show_detailed_analysis(analysis, risk_analysis)
        
        # Show warning if risky
        if risk_analysis["level"] != "SAFE" and not force:
            console.print(format_risk_warning(package_name, risk_analysis))
            
            if not Confirm.ask("Continue anyway?"):
                console.print("❌ Installation cancelled by user")
                return
        
        # Proceed with installation
        console.print(f"📦 Installing {package_name}...")
        
        # Here we would integrate with actual pip
        # For MVP, we'll show what would happen
        _simulate_pip_install(package_name, risk_analysis["level"])
    
    asyncio.run(run_install())


@app.command()
def scan(
    requirements_file: Path = typer.Argument(..., help="Path to requirements.txt file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed analysis")
):
    """Scan requirements file for suspicious packages."""
    
    async def run_scan():
        db = MaliciousPackageDB()
        db.load_initial_data()
        analyzer = PackageAnalyzer(db)
        scorer = RiskScorer()
        
        if not requirements_file.exists():
            console.print(f"❌ File not found: {requirements_file}")
            raise typer.Exit(1)
        
        console.print(f"📋 Scanning {requirements_file}")
        
        # Read requirements
        packages = _parse_requirements(requirements_file)
        
        # Analyze each package
        risky_packages = []
        for package in packages:
            analysis = await analyzer.analyze_package(package)
            risk_analysis = scorer.calculate_risk_score(analysis)
            
            if risk_analysis["level"] != "SAFE":
                risky_packages.append((package, risk_analysis))
                
                if verbose:
                    console.print(f"\n🔍 {package}:")
                    _show_detailed_analysis(analysis, risk_analysis)
        
        # Show summary table
        if risky_packages:
            _show_scan_summary(risky_packages)
        else:
            console.print("✅ No suspicious packages found in requirements file")
    
    asyncio.run(run_scan())


@app.command()
def config(
    setting: str = typer.Argument(None, help="Configuration setting to view/update"),
    value: str = typer.Argument(None, help="Value to set for the setting"),
    show: bool = typer.Option(False, "--show", "-s", help="Show all configuration settings")
):
    """Manage PipGuard configuration settings."""
    
    config_manager = ConfigManager()
    
    if show:
        config_manager.show_config()
        return
    
    if setting is None:
        config_manager.show_config()
        return
    
    if value is None:
        # View specific setting
        current_value = config_manager.get_setting(setting)
        if current_value is not None:
            console.print(f"{setting}: {current_value}")
        else:
            console.print(f"{setting}: <not set>")
    else:
        # Update setting
        config_manager.update_setting(setting, value)


@app.command()
def update(
    force: bool = typer.Option(False, "--force", "-f", help="Force update even if recently updated")
):
    """Update malicious package database from external sources."""
    
    async def run_update():
        db = MaliciousPackageDB()
        console.print("🔄 Updating malicious package database...")
        
        updated_count = await db.update_malicious_database()
        
        if updated_count > 0:
            console.print(f"✅ Updated {updated_count} malicious packages")
        else:
            console.print("ℹ️  No new packages found")
        
        console.print("📦 Database update complete")
    
    asyncio.run(run_update())


@app.command()
def monitor(
    paths: list[Path] = typer.Argument([], help="Paths to monitor (default: current directory)"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Monitor directories recursively")
):
    """Monitor requirements files for changes and auto-scan."""
    
    async def run_monitor():
        from .monitor import start_monitoring
        config = ConfigManager()
        
        if not paths:
            paths = [Path(".")]
        
        await start_monitoring(paths, config)
    
    asyncio.run(run_monitor())


@app.command()
def report(
    path: Path = typer.Argument(".", help="Path to scan (default: current directory)"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json, csv)"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file (default: stdout)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed analysis")
):
    """Generate security audit report."""
    
    def run_report():
        db = MaliciousPackageDB()
        db.load_initial_data()
        analyzer = PackageAnalyzer(db)
        scorer = RiskScorer()
        
        console.print(f"📊 Generating security report for {path}")
        
        # Get packages to analyze
        packages = _get_installed_packages(path)
        
        # Analyze packages
        report_data = []
        for package in packages:
            analysis = asyncio.run(analyzer.analyze_package(package))
            risk_analysis = scorer.calculate_risk_score(analysis)
            
            report_data.append({
                "package": package,
                "risk_level": risk_analysis["level"],
                "risk_score": risk_analysis["score"],
                "reasons": risk_analysis["reasons"]
            })
        
        # Output report
        if format == "json":
            import json
            output_data = json.dumps(report_data, indent=2)
        elif format == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Package", "Risk Level", "Score", "Reasons"])
            for item in report_data:
                writer.writerow([item["package"], item["risk_level"], item["risk_score"], "; ".join(item["reasons"])])
            output_data = output.getvalue()
        else:
            # Table format
            table = Table(title="Security Audit Report")
            table.add_column("Package", style="bold")
            table.add_column("Risk Level", style="bold")
            table.add_column("Score", style="bold")
            table.add_column("Primary Reason", style="bold")
            
            for item in report_data:
                risk_level = item["risk_level"]
                score = item["risk_score"]
                reason = item["reasons"][0] if item["reasons"] else "No issues"
                
                # Color coding
                colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "SAFE": "green"}
                color = colors.get(risk_level, "white")
                
                table.add_row(
                    item["package"],
                    f"[{color}]{risk_level}[/{color}]",
                    str(score),
                    reason[:50] + "..." if len(reason) > 50 else reason
                )
            
            console.print(table)
            return
        
        # Save or print output
        if output:
            with open(output, 'w') as f:
                f.write(output_data)
            console.print(f"📄 Report saved to {output}")
        else:
            console.print(output_data)


@app.command()
def audit(
    path: Path = typer.Argument(".", help="Path to audit (default: current directory)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed analysis")
):
    """Audit current environment for installed packages."""
    
    async def run_audit():
        db = MaliciousPackageDB()
        db.load_initial_data()
        analyzer = PackageAnalyzer(db)
        scorer = RiskScorer()
        
        console.print(f"🔍 Auditing packages in {path}")
        
        # For MVP, we'll check common locations
        installed_packages = _get_installed_packages(path)
        
        risky_packages = []
        for package in installed_packages:
            analysis = await analyzer.analyze_package(package)
            risk_analysis = scorer.calculate_risk_score(analysis)
            
            if risk_analysis["level"] != "SAFE":
                risky_packages.append((package, risk_analysis))
                
                if verbose:
                    console.print(f"\n🔍 {package}:")
                    _show_detailed_analysis(analysis, risk_analysis)
        
        # Show summary
        if risky_packages:
            _show_audit_summary(risky_packages)
        else:
            console.print("✅ No suspicious packages found in environment")
    
    asyncio.run(run_audit())


def _parse_requirements(requirements_file: Path) -> List[str]:
    """Parse requirements.txt and extract package names."""
    packages = []
    
    try:
        with open(requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract package name (handle version specs)
                    package = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                    if package:
                        packages.append(package)
    except Exception as e:
        console.print(f"❌ Error reading requirements file: {e}")
        raise typer.Exit(1)
    
    return packages


def _simulate_pip_install(package_name: str, risk_level: str):
    """Simulate pip install for MVP."""
    colors = {
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue", 
        "SAFE": "green"
    }
    
    color = colors.get(risk_level, "white")
    
    if risk_level == "HIGH":
        console.print(f"⚠️  [bold red]WARNING:[/bold red] Would install {package_name} despite HIGH risk")
    elif risk_level == "MEDIUM":
        console.print(f"⚠️  [bold yellow]WARNING:[/bold yellow] Would install {package_name} with MEDIUM risk")
    else:
        console.print(f"✅ [bold {color}]Installing {package_name}[/bold {color}] (risk level: {risk_level})")
    
    console.print(f"📝 Note: In full version, this would run: pip install {package_name}")


def _show_detailed_analysis(analysis: dict, risk_analysis: dict):
    """Show detailed analysis information."""
    # Package name analysis
    name_analysis = analysis.get("name_analysis", {})
    typosquats = name_analysis.get("typosquats", [])
    
    if typosquats:
        console.print(f"  🎯 Typosquats detected: {typosquats[0][0]} ({typosquats[0][1]:.1%} similar)")
    
    # PyPI info
    pypi_info = analysis.get("pypi_info", {})
    if pypi_info:
        info = pypi_info.get("info", {})
        console.print(f"  📦 PyPI info: {info.get('summary', 'No description')}")
    
    # Risk score breakdown
    console.print(f"  📊 Risk score: {risk_analysis['score']} ({risk_analysis['level']})")


def _show_scan_summary(risky_packages: List[tuple]):
    """Show summary table of risky packages in requirements file."""
    table = Table(title="Suspicious Packages Found")
    table.add_column("Package", style="bold")
    table.add_column("Risk Level", style="bold")
    table.add_column("Score", style="bold")
    table.add_column("Primary Reason", style="bold")
    
    for package, risk_analysis in risky_packages:
        risk_level = risk_analysis["level"]
        score = risk_analysis["score"]
        reason = risk_analysis["reasons"][0] if risk_analysis["reasons"] else "Unknown"
        
        colors = {
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }
        color = colors.get(risk_level, "white")
        
        table.add_row(
            package,
            f"[{color}]{risk_level}[/{color}]",
            str(score),
            reason[:50] + "..." if len(reason) > 50 else reason
        )
    
    console.print(table)


def _show_audit_summary(risky_packages: List[tuple]):
    """Show summary table of risky installed packages."""
    table = Table(title="Risky Installed Packages")
    table.add_column("Package", style="bold")
    table.add_column("Risk Level", style="bold") 
    table.add_column("Score", style="bold")
    table.add_column("Action", style="bold")
    
    for package, risk_analysis in risky_packages:
        risk_level = risk_analysis["level"]
        score = risk_analysis["score"]
        
        colors = {
            "HIGH": "red",
            "MEDIUM": "yellow", 
            "LOW": "blue"
        }
        color = colors.get(risk_level, "white")
        
        action = "🚨 Remove immediately" if risk_level == "HIGH" else "🔍 Review"
        
        table.add_row(
            package,
            f"[{color}]{risk_level}[/{color}]",
            str(score),
            action
        )
    
    console.print(table)


def _get_installed_packages(path: Path) -> List[str]:
    """Get list of installed packages (MVP implementation)."""
    # For MVP, check common locations
    packages = []
    
    # Check for requirements.txt and parse it
    req_files = list(path.rglob("requirements*.txt"))
    for req_file in req_files:
        try:
            with open(req_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        package = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                        if package and package not in packages:
                            packages.append(package)
        except:
            continue
    
    # In a full implementation, we'd check pip list or environment
    return packages


def main():
    """Main entry point for PipGuard CLI."""
    app()


if __name__ == "__main__":
    main()
