"""
Configuration management for PipGuard.
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class PipGuardConfig:
    """Configuration settings for PipGuard."""
    auto_update: bool = True
    update_interval_hours: int = 24
    allowlist: list = None
    block_high_risk: bool = False
    notifications_enabled: bool = True
    log_level: str = "INFO"
    database_path: Optional[str] = None


class ConfigManager:
    """Manages PipGuard configuration."""
    
    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path.home() / ".pipguard" / "config.json"
        
        self.config_path = config_path
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
    
    def load_config(self) -> PipGuardConfig:
        """Load configuration from file."""
        if not self.config_path.exists():
            return PipGuardConfig()
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
                return PipGuardConfig(**data)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            return PipGuardConfig()
    
    def save_config(self, config: PipGuardConfig):
        """Save configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(asdict(config), f, indent=2)
        except Exception as e:
            print(f"Error: Could not save config: {e}")
    
    def update_setting(self, key: str, value: Any):
        """Update a single configuration setting."""
        config = self.load_config()
        if hasattr(config, key):
            setattr(config, key, value)
            self.save_config(config)
            print(f"✅ Updated {key} = {value}")
        else:
            print(f"❌ Unknown setting: {key}")
    
    def get_setting(self, key: str) -> Any:
        """Get a single configuration setting."""
        config = self.load_config()
        if hasattr(config, key):
            return getattr(config, key)
        return None
    
    def show_config(self):
        """Display current configuration."""
        config = self.load_config()
        config_dict = asdict(config)
        
        print("📋 PipGuard Configuration:")
        for key, value in config_dict.items():
            if value is not None:
                print(f"  {key}: {value}")
            else:
                print(f"  {key}: <not set>")
