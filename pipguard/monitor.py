"""
File monitoring functionality for PipGuard.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .database import MaliciousPackageDB
from .analyzer import PackageAnalyzer
from .risk_scorer import RiskScorer
from .config import ConfigManager


class RequirementsHandler(FileSystemEventHandler):
    """Handle file system events for requirements files."""
    
    def __init__(self, db: MaliciousPackageDB, analyzer: PackageAnalyzer, scorer: RiskScorer):
        self.db = db
        self.analyzer = analyzer
        self.scorer = scorer
        self.last_scan = {}
    
    async def scan_file(self, file_path: Path):
        """Scan a requirements file for suspicious packages."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Extract package names
            packages = []
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    package = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                    if package:
                        packages.append(package)
            
            if not packages:
                return
            
            # Analyze packages
            risky_packages = []
            for package in packages:
                analysis = await self.analyzer.analyze_package(package)
                risk_analysis = self.scorer.calculate_risk_score(analysis)
                
                if risk_analysis["level"] != "SAFE":
                    risky_packages.append((package, risk_analysis))
            
            if risky_packages:
                print(f"\n⚠️  PipGuard Alert: Suspicious packages found in {file_path.name}")
                for package, risk in risky_packages:
                    print(f"  🚨 {package}: {risk['level']} risk (score: {risk['score']})")
                    for reason in risk['reasons']:
                        print(f"    - {reason}")
            else:
                print(f"✅ PipGuard: No suspicious packages in {file_path.name}")
                
        except Exception as e:
            print(f"❌ Error scanning {file_path}: {e}")
    
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path.name in ['requirements.txt', 'requirements-dev.txt', 'requirements.in']:
            # Debounce rapid changes
            current_time = time.time()
            last_scan_time = self.last_scan.get(str(file_path), 0)
            
            if current_time - last_scan_time > 5:  # 5 second debounce
                self.last_scan[str(file_path)] = current_time
                print(f"\n📁 PipGuard: Changes detected in {file_path.name}")
                asyncio.create_task(self.scan_file(file_path))
    
    def on_created(self, event):
        """Handle file creation events."""
        self.on_modified(event)


async def start_monitoring(paths: List[Path], config: ConfigManager):
    """Start monitoring requirements files for changes."""
    db = MaliciousPackageDB()
    db.load_initial_data()
    analyzer = PackageAnalyzer(db)
    scorer = RiskScorer()
    
    # Create event handler
    event_handler = RequirementsHandler(db, analyzer, scorer)
    
    # Set up file system observer
    observer = Observer()
    
    # Watch each path for requirements files
    for path in paths:
        if path.is_file() and path.name in ['requirements.txt', 'requirements-dev.txt', 'requirements.in']:
            # Watch the directory containing the file
            watch_path = path.parent
        else:
            watch_path = path
        
        observer.schedule(event_handler, str(watch_path), recursive=False)
        print(f"👀 PipGuard: Monitoring {watch_path}")
    
    observer.start()
    
    try:
        print("🔍 PipGuard monitor started (Ctrl+C to stop)")
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 PipGuard monitor stopped")
        observer.stop()
        observer.join()
