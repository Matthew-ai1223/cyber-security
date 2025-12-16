#!/usr/bin/env python3
"""
Installation script for Ethical Hacking Tools Suite
Handles Windows-specific installation issues
"""

import subprocess
import sys
import os

def install_requirements():
    """
    Install requirements with Windows-specific handling
    """
    print("Installing Ethical Hacking Tools Suite dependencies...")
    
    # Core packages that should install without issues
    core_packages = [
        "scapy>=2.4.5",
        "requests>=2.28.0", 
        "beautifulsoup4>=4.11.0",
        "cryptography>=3.4.8",
        "bcrypt>=4.0.0",
        "passlib>=1.7.4",
        "argon2-cffi>=21.3.0",
        "pynput>=1.7.6",
        "keyboard>=0.13.5",
        "psutil>=5.9.0",
        "selenium>=4.8.0",
        "urllib3>=1.26.0",
        "pymysql>=1.0.2",
        "colorama>=0.4.6",
        "termcolor>=2.2.0",
        "tqdm>=4.64.0"
    ]
    
    # Packages that might have issues on Windows
    optional_packages = [
        "netifaces>=0.11.0"  # Requires Visual C++ Build Tools
    ]
    
    print("\n[+] Installing core packages...")
    for package in core_packages:
        try:
            print(f"Installing {package}...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], 
                         check=True, capture_output=True)
            print(f"✓ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install {package}: {e}")
    
    print("\n[+] Attempting to install optional packages...")
    for package in optional_packages:
        try:
            print(f"Installing {package}...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], 
                         check=True, capture_output=True)
            print(f"✓ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"⚠ {package} failed to install (this is expected on Windows without Visual C++ Build Tools)")
            print(f"  Error: {e}")
    
    print("\n[+] Installation completed!")
    print("\nNote: Some packages may not be available on Windows without Visual C++ Build Tools.")
    print("The tools will work with reduced functionality for those features.")

def check_installation():
    """
    Check if installation was successful
    """
    print("\n[+] Checking installation...")
    
    required_modules = [
        "scapy",
        "requests", 
        "bs4",  # beautifulsoup4 installs as bs4
        "cryptography",
        "bcrypt",
        "passlib",
        "pynput",
        "psutil",
        "colorama",
        "termcolor",
        "tqdm"
    ]
    
    optional_modules = [
        "netifaces",
        "selenium",
        "keyboard"
    ]
    
    print("Required modules:")
    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module} - MISSING!")
    
    print("\nOptional modules:")
    for module in optional_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"⚠ {module} - Not available (optional)")

if __name__ == "__main__":
    print("Ethical Hacking Tools Suite - Installation Script")
    print("=" * 50)
    
    install_requirements()
    check_installation()
    
    print("\n" + "=" * 50)
    print("Installation complete!")
    print("You can now run: python main.py --help")
