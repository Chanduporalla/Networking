"""
QUICK START GUIDE - Network Traffic Analyzer
A quick reference for getting the application running
"""

# ============================================================================
# QUICK START - 5 MINUTES
# ============================================================================

# Step 1: Install Dependencies
# Command line:
#   pip install -r requirements.txt
#
# Or manually:
#   pip install scapy matplotlib

# Step 2: Run the Application
#   python main.py

# Step 3: Load a PCAP File
# - Click "📁 Open PCAP File" button
# - Select a .pcap or .pcapng file
# - Wait for parsing to complete

# Step 4: Analyze Traffic
# - View packets in the table (bottom-left)
# - See visualizations in top panel
# - Click "🔍 Analyze Traffic" for AI insights

# ============================================================================
# WHERE TO GET SAMPLE PCAP FILES
# ============================================================================

# Option 1: Wireshark Sample Captures
#   Download: https://wiki.wireshark.org/SampleCaptures
#   Popular files:
#   - http.pcap (HTTP traffic)
#   - ftp-data-transfer.pcap (FTP traffic)
#   - dns.pcap (DNS queries)
#   - ssl-keys.pcap (HTTPS traffic)

# Option 2: Create Your Own Capture
# Using Wireshark:
#   1. Open Wireshark
#   2. Click Capture → Capture Options
#   3. Select your network interface
#   4. Click Start
#   5. Generate some network traffic (visit websites, ping, etc.)
#   6. File → Save (choose .pcap format)

# Using tcpdump (Linux/macOS):
#   sudo tcpdump -i en0 -w myCapture.pcap
#   (Replace en0 with your network interface)

# ============================================================================
# APPLICATION LAYOUT
# ============================================================================

# ┌──────────────────────────────────────────────────────────────────────┐
# │ [📁 Open PCAP File] [No file loaded] [Status: Ready]                 │
# ├──────────────────────────────────────────────────────────────────────┤
# │                    📊 Traffic Visualization                           │
# │  ┌─────────────────────────────────────────────────────────────────┐  │
# │  │                                                                 │  │
# │  │  [Pie Chart: Protocol]      [Line Graph: Timeline]             │  │
# │  │   Distribution                Packet Count Over Time           │  │
# │  │                                                                 │  │
# │  └─────────────────────────────────────────────────────────────────┘  │
# ├──────────────┬──────────────────────────────────────────────────────┤
# │ 📋 Packet    │ 🤖 AI Traffic Analysis                              │
# │ Details      │ ┌────────────────────────────────────────────────┐ │
# │              │ │[🔍 Analyze Traffic] [📥 Export Report]       │ │
# │ [Packet Table]│ │                                              │ │
# │  # Time SrcIP│ │  Analysis Results:                             │ │
# │              │ │  • Protocol Distribution                       │ │
# │ 1 10:00 ...  │ │  • Suspicious Activity Indicators             │ │
# │ 2 10:01 ...  │ │  • Network Recommendations                    │ │
# │ 3 10:02 ...  │ │  • IP Reputation Analysis                     │ │
# │              │ │                                              │ │
# │ [Details Panel]│ │                                              │ │
# │ Selected     │ │                                              │ │
# │ Packet Info  │ │                                              │ │
# │              │ └────────────────────────────────────────────────┘ │
# └──────────────┴──────────────────────────────────────────────────────┘

# ============================================================================
# KEY FEATURES EXPLAINED
# ============================================================================

# 📊 TRAFFIC VISUALIZATION
#   • Pie Chart: Shows protocol distribution (TCP, UDP, DNS, etc.)
#   • Line Graph: Displays packet count over time
#   • Updates automatically after loading PCAP file
#   • Helps identify traffic patterns at a glance

# 📋 PACKET DETAILS
#   • Displays all parsed packets in a scrollable table
#   • Columns: Packet #, Time, Source IP, Dest IP, Protocol, Length
#   • Click on any packet to see full details below table
#   • Shows all packet metadata (ports, flags, etc.)

# 🤖 AI ANALYSIS
#   • Summarizes traffic patterns automatically
#   • Detects suspicious activity indicators
#   • Identifies potential threats or anomalies
#   • Provides network optimization recommendations
#   • Click "Analyze Traffic" to generate report
#   • Export results to text file with "Export Report"

# ============================================================================
# COMMON TASKS
# ============================================================================

# Task 1: View Protocol Breakdown
#   1. Load PCAP file
#   2. Check pie chart in visualization panel
#   3. Hover over pie slices for percentages

# Task 2: Find Packets from Specific IP
#   1. Load PCAP file
#   2. Check "Top Source/Dest IPs" statistics
#   3. Scroll through packet table to find matching packets

# Task 3: Analyze Suspicious Traffic
#   1. Load PCAP file
#   2. Click "Analyze Traffic"
#   3. Review "SUSPICIOUS INDICATORS" section
#   4. Check "RECOMMENDATIONS" for security actions

# Task 4: Save Analysis Report
#   1. Load PCAP and run analysis
#   2. Click "Export Report"
#   3. Choose location and filename
#   4. Report saved as formatted text file

# ============================================================================
# TROUBLESHOOTING
# ============================================================================

# Problem: "No module named 'scapy'"
#   Solution: pip install scapy

# Problem: "No module named 'matplotlib'"
#   Solution: pip install matplotlib

# Problem: Application won't start
#   Solution: Run setup_check.py to diagnose
#   Command: python setup_check.py

# Problem: PCAP file won't open
#   Solution:
#   - Verify file extension is .pcap or .pcapng
#   - Check file is not corrupted (try with sample file)
#   - Ensure file permissions allow reading

# Problem: No visualizations appear
#   Solution:
#   - Reinstall matplotlib: pip install --upgrade matplotlib
#   - Check that PCAP file actually contains packets
#   - Restart application

# ============================================================================
# KEYBOARD SHORTCUTS
# ============================================================================

# Ctrl+O        Open PCAP file
# Ctrl+E        Export report (when analysis complete)
# Tab           Navigate between panels
# Enter         Select highlighted packet
# Escape        Deselect packet

# ============================================================================
# TIPS FOR NETWORK ENGINEERS
# ============================================================================

# 1. Use with Wireshark
#    - Create captures in Wireshark
#    - Use Traffic Analyzer for automated analysis
#    - Compare manual inspection with AI insights

# 2. Analyze Specific Traffic
#    - In Wireshark, filter traffic: tcp.port == 80
#    - Save filtered capture
#    - Load in Traffic Analyzer for focused analysis

# 3. Learn Network Protocols
#    - Load sample captures
#    - Inspect packet details
#    - Compare with Wireshark analysis
#    - Study protocol headers and payloads

# 4. Practice for CCNA/CCNP
#    - Analyze different protocol captures
#    - Understand TCP handshake in detail
#    - Learn DNS resolution process
#    - Practice threat detection

# ============================================================================
# PERFORMANCE NOTES
# ============================================================================

# Application Performance:
#   • Small files (< 100MB): Instant loading
#   • Medium files (100-500MB): 5-15 seconds
#   • Large files (> 500MB): May take 30+ seconds

# For Large Captures:
#   1. Filter traffic before analysis: tcpdump -r input.pcap -w output.pcap "tcp port 80"
#   2. Close other applications
#   3. Be patient - processing happens in background
#   4. UI remains responsive during analysis

# ============================================================================
# EXTENDING THE APPLICATION
# ============================================================================

# Add Custom Protocol Support:
#   Edit: packet_parser.py
#   Modify: _extract_packet_info() method
#   Add your protocol import and detection

# Integrate Threat Intelligence API:
#   Edit: ai_analysis.py
#   Modify: _check_suspicious_activity() method
#   Call your API for real-time threat checking

# Add Custom Visualizations:
#   Edit: visualization.py
#   Create: new method (e.g., create_custom_chart)
#   Call from: ui.py in _create_visualizations()

# ============================================================================
# SUPPORT & DOCUMENTATION
# ============================================================================

# README.md       - Comprehensive documentation
# setup_check.py  - System verification and setup
# Code Comments   - Detailed explanation in each module

# External Resources:
#   Scapy: https://scapy.readthedocs.io/
#   Matplotlib: https://matplotlib.org/docs/
#   Wireshark: https://www.wireshark.org/docs/
#   TCPDUMP: https://www.tcpdump.org/

# ============================================================================

print("""
╔════════════════════════════════════════════════════════════════════╗
║      Network Traffic Analyzer - Quick Start Complete              ║
╚════════════════════════════════════════════════════════════════════╝

Ready to get started? Follow these steps:

1. Install dependencies:
   $ pip install -r requirements.txt

2. Run the application:
   $ python main.py

3. Load a sample PCAP file:
   Download from: https://wiki.wireshark.org/SampleCaptures
   Or create one with Wireshark

4. Analyze and enjoy!

For more details, see README.md

Happy Analyzing! 🚀
═════════════════════════════════════════════════════════════════════
""")
