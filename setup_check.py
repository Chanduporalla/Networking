"""
Setup and Configuration Guide for Network Traffic Analyzer
Provides step-by-step instructions for first-time setup
"""

import sys
import subprocess
from pathlib import Path


def check_python_version():
    """Verify Python 3.8+ is installed."""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required. Current version:", sys.version)
        return False
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True


def check_and_install_packages():
    """Check and install required packages."""
    required_packages = {
        'scapy': 'scapy>=2.4.5',
        'matplotlib': 'matplotlib>=3.3.0',
    }
    
    print("\n📦 Checking required packages...")
    
    for package_name, package_spec in required_packages.items():
        try:
            __import__(package_name)
            print(f"✓ {package_name} is installed")
        except ImportError:
            print(f"⚠️  {package_name} not found. Installing...")
            try:
                subprocess.check_call([
                    sys.executable, '-m', 'pip', 'install', package_spec
                ])
                print(f"✓ {package_name} installed successfully")
            except subprocess.CalledProcessError:
                print(f"❌ Failed to install {package_name}")
                return False
    
    return True


def check_tkinter():
    """Check if Tkinter is available (usually pre-installed)."""
    try:
        import tkinter
        print("✓ Tkinter is installed")
        return True
    except ImportError:
        print("❌ Tkinter not found")
        print("   Install with:")
        print("   - Windows: Python installer should include Tkinter")
        print("   - Ubuntu/Debian: sudo apt-get install python3-tk")
        print("   - macOS: brew install python-tk")
        return False


def create_sample_pcap_info():
    """Provide information about obtaining sample PCAP files."""
    print("\n📝 Sample PCAP Files")
    print("─" * 50)
    print("You'll need a .pcap or .pcapng file to analyze.")
    print("\nOptions:")
    print("1. Download sample captures:")
    print("   https://wiki.wireshark.org/SampleCaptures")
    print("\n2. Capture your own traffic with Wireshark:")
    print("   - Download: https://www.wireshark.org")
    print("   - File → Capture → Start")
    print("   - File → Save (choose .pcap format)")
    print("\n3. Use tcpdump (Linux/macOS):")
    print("   sudo tcpdump -i eth0 -w capture.pcap")
    print("\n4. Use Cisco Modeling Labs or GNS3 captures")


def run_startup_check():
    """Run complete startup check."""
    print("\n" + "=" * 60)
    print("  NETWORK TRAFFIC ANALYZER - STARTUP CHECK")
    print("=" * 60)
    
    all_good = True
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check Tkinter
    print("\n🖼️  Checking GUI framework...")
    if not check_tkinter():
        all_good = False
    
    # Check and install packages
    print()
    if not check_and_install_packages():
        return False
    
    # Show info about sample files
    create_sample_pcap_info()
    
    # Final status
    print("\n" + "=" * 60)
    if all_good:
        print("✅ Setup Complete! You're ready to run the application.")
        print("\n   Run: python main.py")
    else:
        print("⚠️  Setup complete with warnings. See above for details.")
    print("=" * 60 + "\n")
    
    return True


if __name__ == "__main__":
    success = run_startup_check()
    sys.exit(0 if success else 1)
