#!/usr/bin/env python3
"""
Ethical Hacking Tools Suite - Web GUI Launcher
Educational and Testing Purposes Only

Launches the web-based GUI for the Ethical Hacking Tools Suite
"""

import os
import sys
import webbrowser
import time
import subprocess
import threading
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = ['flask', 'flask_cors']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"[!] Missing required packages: {', '.join(missing_packages)}")
        print("[+] Installing missing packages...")
        
        for package in missing_packages:
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                             check=True, capture_output=True)
                print(f"✓ {package} installed successfully")
            except subprocess.CalledProcessError as e:
                print(f"✗ Failed to install {package}: {e}")
                return False
    
    return True

def create_directories():
    """Create necessary directories"""
    directories = ['static/css', 'static/js', 'templates', 'logs']
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✓ Directory structure created")

def open_browser():
    """Open browser after a short delay"""
    time.sleep(2)
    webbrowser.open('http://localhost:5000')

def main():
    """Main launcher function"""
    print("Ethical Hacking Tools Suite - Web GUI Launcher")
    print("=" * 50)
    print("WARNING: This is for educational purposes only!")
    print("Use only on systems you own or have permission to test!")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("[!] Failed to install required dependencies")
        return
    
    # Create directories
    create_directories()
    
    # Check if web_gui.py exists
    if not os.path.exists('web_gui.py'):
        print("[!] Error: web_gui.py not found")
        print("[!] Make sure you're running this from the project root directory")
        return
    
    print("\n[+] Starting web server...")
    print("[+] Server will be available at: http://localhost:5000")
    print("[+] Press Ctrl+C to stop the server")
    print("\n" + "=" * 50)
    
    # Open browser in a separate thread
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    try:
        # Start the Flask server
        subprocess.run([sys.executable, 'web_gui.py'])
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user")
    except Exception as e:
        print(f"[!] Server error: {e}")

if __name__ == "__main__":
    main()
