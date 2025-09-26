#!/usr/bin/env python3
"""
PhishHunter Installation and Setup Script
Author: Ali AlEnezi

This script helps users install and configure PhishHunter for optimal performance.
"""

import os
import sys
import json
import subprocess
import platform
from pathlib import Path

class PhishHunterInstaller:
    """PhishHunter installation and configuration helper"""

    def __init__(self):
        self.python_version = sys.version_info
        self.os_type = platform.system()
        self.home_dir = Path.home()
        self.install_dir = Path.cwd()

    def check_system_requirements(self):
        """Check system requirements"""
        print("🔍 Checking System Requirements...")

        # Check Python version
        if self.python_version < (3, 7):
            print("❌ Python 3.7+ is required")
            print(f"   Current version: {sys.version}")
            return False
        else:
            print(f"✅ Python {sys.version.split()[0]} detected")

        # Check pip
        try:
            subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                          check=True, capture_output=True)
            print("✅ pip is available")
        except subprocess.CalledProcessError:
            print("❌ pip is not available")
            return False

        return True

    def install_dependencies(self):
        """Install required dependencies"""
        print("\n📦 Installing Dependencies...")

        try:
            # Install main requirements
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], check=True)
            print("✅ Main dependencies installed")

        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False

        return True

    def create_configuration(self):
        """Create initial configuration"""
        print("\n⚙️ Setting up Configuration...")

        config_path = self.install_dir / 'config.json'

        if config_path.exists():
            print("📁 Configuration file already exists")
            return True

        # Create default configuration
        config = {
            "api_keys": {
                "virustotal": "",
                "urlscan": ""
            },
            "detection_settings": {
                "confidence_threshold": 0.7,
                "max_workers": 5,
                "timeout": 30,
                "enable_ml": True
            },
            "phishing_keywords": [
                "login", "secure", "account", "verify", "update"
            ]
        }

        # Save configuration
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuration saved to {config_path}")
        return True

    def show_usage_examples(self):
        """Show usage examples"""
        print("\n📚 Usage Examples:")
        print("=" * 50)

        examples = [
            ("Basic scan", "python phishhunter.py https://suspicious-site.com"),
            ("Multiple URLs", "python phishhunter.py site1.com site2.com"),
            ("From file", "python phishhunter.py -f urls.txt"),
            ("Save results", "python phishhunter.py https://site.com -o results.json")
        ]

        for description, command in examples:
            print(f"  {description:15} {command}")

    def install(self):
        """Main installation process"""
        print("🎣 PhishHunter Installation")
        print("=" * 50)
        print("Author: Ali AlEnezi <site@hotmail.com>")
        print("GitHub: https://github.com/SiteQ8/phishhunter")
        print("=" * 50)

        # Check system requirements
        if not self.check_system_requirements():
            print("\n❌ System requirements not met")
            return False

        # Install dependencies
        if not self.install_dependencies():
            print("\n❌ Dependency installation failed")
            return False

        # Create configuration
        if not self.create_configuration():
            print("\n❌ Configuration setup failed")
            return False

        # Show usage examples
        self.show_usage_examples()

        print("\n🎉 PhishHunter installation completed!")
        print("\n🚀 Quick Start:")
        print(f"   python phishhunter.py https://suspicious-site.com")

        return True

if __name__ == '__main__':
    installer = PhishHunterInstaller()

    try:
        success = installer.install()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Installation failed: {e}")
        sys.exit(1)
