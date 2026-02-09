"""
Network Traffic Analyzer - Main Application Entry Point
A desktop application for analyzing network traffic capture files (.pcap/.pcapng)
with visualizations and traffic analysis capabilities.

Author: Network Engineering Suite
License: MIT
"""

import tkinter as tk
from tkinter import messagebox
import sys
import os

# Add project root to path for imports
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from ui import NetworkAnalyzerApp


def main():
    """
    Initialize and run the Network Traffic Analyzer application.
    """
    try:
        # Create root window
        root = tk.Tk()
        
        # Initialize application
        app = NetworkAnalyzerApp(root)
        
        # Start the application
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror(
            "Application Error",
            f"Failed to start Network Traffic Analyzer:\n{str(e)}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
