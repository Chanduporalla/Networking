# Network Traffic Analyzer - Complete Project Explanation

## 📋 Project Overview

**Network Traffic Analyzer** is a desktop application that allows network engineers and security professionals to analyze network packet capture files (.pcap/.pcapng) with a visual interface similar to Wireshark but focused on traffic analysis and AI-powered insights.

### **Key Purpose:**
- Load and parse network packet captures
- Visualize traffic patterns and statistics
- Detect suspicious network behavior
- Generate comprehensive analysis reports

---

## 🏗️ Architecture & Project Structure

```
/CCNA&&CCNP/PROJECTS/
├── main.py                    # Entry point - launches the application
├── ui.py                      # GUI interface with Tkinter
├── packet_parser.py           # PCAP file parsing using Scapy
├── visualization.py           # Chart generation using Matplotlib
├── ai_analysis.py             # Analysis engine for traffic insights
├── generate_sample_pcap.py    # Script to generate test traffic
├── sample_traffic.pcap        # Sample PCAP file (66 packets)
├── requirements.txt           # Python dependencies
├── README.md                  # Quick start guide
└── PROJECT_EXPLANATION.md     # This file
```

### **Design Pattern: Modular & Object-Oriented**

Each module is independent and can be used separately:
```
┌─────────────────────────────────────────┐
│         main.py (Entry Point)           │
│    Creates Tkinter root window          │
└────────────────┬────────────────────────┘
                 │
        ┌────────▼───────────┐
        │   ui.py (GUI)      │
        │ NetworkAnalyzerApp │
        └────────┬───────────┘
                 │
      ┌──────────┼──────────┐
      │          │          │
      ▼          ▼          ▼
packet_parser visualization ai_analysis
    .py          .py          .py
```

---

## 🔴 MAIN.PY - Application Entry Point

### **What It Does:**
- Initializes the Tkinter root window
- Launches the NetworkAnalyzerApp
- Handles application-level errors

### **Complete Code:**

```python
"""
Network Traffic Analyzer - Main Application Entry Point
"""

import tkinter as tk
from tkinter import messagebox
import sys
import os

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from ui import NetworkAnalyzerApp


def main():
    """Initialize and run the Network Traffic Analyzer application."""
    try:
        root = tk.Tk()
        app = NetworkAnalyzerApp(root)
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror(
            "Application Error",
            f"Failed to start Network Traffic Analyzer:\n{str(e)}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
```

**How to Run:**
```bash
python3 main.py
```

---

## 🔵 UI.PY - Graphical User Interface

### **What It Does:**
- Creates the main window layout
- Manages all user interactions
- Coordinates between modules
- Displays results and analysis

### **Window Layout (Flexible/Resizable):**

```
┌─────────────────────────────────────────────────────────────┐
│                         TOOLBAR                             │
│   [📁 Open File]  File: sample_traffic.pcap  Ready ✓        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│        📊 TRAFFIC VISUALIZATION (TOP - Resizable)           │
│                                                               │
│  - Protocol Distribution (Pie Chart)                         │
│  - Packet Timeline (Line Chart)                              │
│  - Source/Destination IPs (Bar Chart)                        │
│                                                               │
├──────────────────────────────┬────────────────────────────────┤
│                              │                                │
│  📋 PACKET DETAILS           │  🤖 AI ANALYSIS                │
│   (Resizable Left)           │   (Resizable Right)            │
│                              │                                │
│ Packet# Time  Src IP Dst IP  │ [🔍 Analyze] [📥 Export]      │
│ ─────────────────────────    │                                │
│ 1      12:34  192...  8.8... │ Protocol Distribution:         │
│ 2      12:34  192...  1.1... │ • TCP: 35 packets (53%)        │
│ 3      12:34  192...  8.8... │ • UDP: 20 packets (30%)        │
│                              │ • ICMP: 8 packets (12%)        │
│ Selected Packet Details:     │                                │
│ Src: 192.168.1.100:53892     │ Suspicious Activity:           │
│ Dst: 8.8.8.8:53              │ ⚠️  Port Scan Detected         │
│ Protocol: UDP (DNS)          │ ⚠️  Large Data Transfer        │
│ Length: 68 bytes             │                                │
└──────────────────────────────┴────────────────────────────────┘
```

### **Key Classes & Methods:**

#### **NetworkAnalyzerApp Class:**
```python
class NetworkAnalyzerApp:
    def __init__(self, root: tk.Tk)
    def _build_ui()              # Build layout
    def _build_toolbar()         # Create toolbar
    def _build_packet_details_panel()  # Left panel
    def _build_ai_analysis_panel()     # Right panel
    def _on_load_file()          # Load PCAP file
    def _on_packet_selected()    # When packet clicked
    def _on_analyze_traffic()    # Run analysis
    def _on_export_report()      # Save report
    def _update_visualizations() # Refresh charts
    def _populate_packet_table() # Fill table with packets
```

### **Main UI Features:**

1. **Flexible Layout**
   - Drag panel dividers to resize
   - Top panel for graphs
   - Bottom-left for packet table
   - Bottom-right for analysis

2. **Interactive Elements**
   - File upload button
   - Packet selection
   - Analysis triggers
   - Report export

3. **Real-time Updates**
   - Status indicators
   - Progress messages
   - Dynamic chart updates

---

## 🟢 PACKET_PARSER.PY - PCAP File Parser

### **What It Does:**
- Reads .pcap/.pcapng files using Scapy library
- Extracts packet information
- Calculates statistics
- Formats data for display

### **Key Classes & Methods:**

#### **PacketParser Class:**
```python
class PacketParser:
    def __init__()
    def load_pcap_file(file_path: str) -> bool
    def _parse_packets()                    # Parse all packets
    def _extract_packet_info(packet, idx)   # Extract single packet
    def _update_statistics(packet_info)     # Update stats
    def get_protocol_statistics()           # Return protocol stats
    def get_ip_statistics()                 # Return IP stats
    def get_packet_details(packet_num)      # Get specific packet
```

### **Network Packet Structure:**

```
┌─────────────────────────────────────────────┐
│          Packet Frame (Ethernet)            │
├─────────────────────────────────────────────┤
│              IP Header Layer                │
│  Source IP: 192.168.1.100                  │
│  Dest IP: 8.8.8.8                          │
│  Protocol: TCP/UDP/ICMP                    │
├─────────────────────────────────────────────┤
│         Transport Layer (TCP/UDP)           │
│  Source Port: 53892                        │
│  Dest Port: 53 (DNS)                       │
│  Flags: SYN, ACK, FIN, etc.                │
├─────────────────────────────────────────────┤
│          Application Layer Data            │
│  HTTP, DNS, SSH, HTTPS, etc.               │
└─────────────────────────────────────────────┘
```

### **Example Packet Information:**

```python
packet_info = {
    'number': 1,                    # Packet sequence number
    'timestamp': 1649123456.123,    # Unix timestamp
    'time_str': '12:34:56.123',     # Formatted time
    'src_ip': '192.168.1.100',      # Source IP
    'dst_ip': '8.8.8.8',            # Destination IP
    'protocol': 'UDP',              # Protocol type
    'length': 68,                   # Packet size in bytes
    'src_port': 53892,              # Source port
    'dst_port': 53,                 # Destination port (DNS)
    'info': 'Query: google.com',    # Additional info
    'raw_packet': <Scapy Packet>    # Raw packet object
}
```

### **Protocol Detection Logic:**

```python
def _extract_packet_info(packet, packet_num):
    if IP in packet:
        if TCP in packet:
            protocol = 'TCP'
            extract TCP headers (sport, dport, flags)
        elif UDP in packet:
            protocol = 'UDP'
            if DNS in packet:
                protocol = 'DNS'
            if NTP in packet:
                protocol = 'NTP'
        elif ICMP in packet:
            protocol = 'ICMP'
    elif ARP in packet:
        protocol = 'ARP'
```

---

## 🟠 VISUALIZATION.PY - Chart Generation

### **What It Does:**
- Creates Matplotlib charts
- Embeds charts into Tkinter
- Generates various traffic visualizations
- Updates dynamically

### **Key Classes & Methods:**

#### **TrafficVisualizer Class:**
```python
class TrafficVisualizer:
    def create_protocol_distribution_chart()  # Pie chart
    def create_packet_timeline_chart()        # Line chart
    def create_top_ips_chart()                # Bar chart
    def create_combined_dashboard()           # Multi-subplot view
```

### **Chart Types:**

1. **Protocol Distribution (Pie Chart)**
```
        TCP
      /     \
   35%       20% UDP
    /           \
   /             \
ICMP  ICMP-ECHO
12%    15%
  \            /
   \          /
    DNS-18% /
```

2. **Packet Timeline (Line Chart)**
```
Count |     ╱╲
      |    ╱  ╲╱╲
    5 |___╱____╲__╲___
      |      packet   seconds
    0 |________________
      0  1  2  3  4  5  6
```

3. **Top Source IPs (Bar Chart)**
```
IP Address        Packets
192.168.1.100     ████████ 25
192.168.1.101     ██████ 18
10.0.0.50         ███████ 21
192.168.1.102     ████ 12
```

### **Chart Creation Example:**

```python
def create_protocol_distribution_chart(protocol_stats, parent_frame):
    # Create Matplotlib figure
    fig = Figure(figsize=(5, 4), dpi=100)
    ax = fig.add_subplot(111)
    
    # Prepare data
    protocols = list(protocol_stats.keys())
    counts = list(protocol_stats.values())
    
    # Draw pie chart
    ax.pie(counts, labels=protocols, autopct='%1.1f%%')
    ax.set_title('Protocol Distribution')
    
    # Embed in Tkinter
    canvas = FigureCanvasTkAgg(fig, master=parent_frame)
    canvas.draw()
    return canvas
```

---

## 🟡 AI_ANALYSIS.PY - Traffic Analysis Engine

### **What It Does:**
- Analyzes traffic patterns
- Detects suspicious activity
- Generates security insights
- Provides recommendations

### **Key Classes & Methods:**

#### **AIAnalyzer Class:**
```python
class AIAnalyzer:
    def analyze_traffic(packet_details, protocol_stats, ip_stats)
    def _analyze_protocols()             # Protocol insights
    def _detect_traffic_patterns()       # Pattern detection
    def _check_suspicious_activity()     # Threat detection
    def _analyze_ip_reputation()         # IP analysis
    def _generate_recommendations()      # Suggestions
    def _format_analysis_report()        # Format output
```

### **Analysis Output Example:**

```
═══════════════════════════════════════════════════════════
                   TRAFFIC ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Timestamp: 2026-02-09 14:30:45

📊 OVERALL STATISTICS
────────────────────────────────────────────────────────────
Total Packets: 66
Total Data: 28.5 KB
Capture Duration: 3.3 seconds
Average Packet Size: 432 bytes

🔵 PROTOCOL ANALYSIS
────────────────────────────────────────────────────────────
Top Protocols:
  1. TCP        - 35 packets (53.0%)
  2. UDP        - 20 packets (30.3%)
  3. ICMP       -  8 packets (12.1%)
  4. ARP        -  3 packets ( 4.5%)

🔍 TRAFFIC PATTERNS
────────────────────────────────────────────────────────────
Unicast Packets: 63 (95.5%)
Broadcast Packets: 3 (4.5%)
Large Packets (>1000B): 2
Small Packets (<100B): 15
Average Packet Size: 432 bytes

⚠️  SUSPICIOUS ACTIVITY DETECTED
────────────────────────────────────────────────────────────
[MEDIUM] Port Scanning Activity
  From: 192.168.1.105
  Ports Scanned: 21, 22, 23, 25, 3389
  Risk: Reconnaissance attempt

[LOW] Unusual Data Transfer
  From: 192.168.1.100 to 203.0.113.50
  Size: 2.8 KB
  Port: 443 (HTTPS)
  Note: Suspicious external IP

[INFO] DNS Queries
  google.com, github.com, stackoverflow.com
  Status: Normal behavior

🌐 IP REPUTATION ANALYSIS
────────────────────────────────────────────────────────────
Internal IPs: 4 (192.168.1.0/24, 10.0.0.0/24)
External IPs: 5 (Public internet)
Suspicious IPs: 1 (203.0.113.0/24 - Reserved range)

💡 RECOMMENDATIONS
────────────────────────────────────────────────────────────
1. Investigate source 192.168.1.105 - Port scanning detected
2. Monitor connections to 203.0.113.50 (suspicious external IP)
3. Whitelist known DNS servers to reduce alert noise
4. Set up IDS rules for port scan patterns
5. Review DNS query patterns for data exfiltration

═══════════════════════════════════════════════════════════
```

### **Suspicious Pattern Detection:**

```python
suspicious_patterns = {
    'port_scanning': [
        Multiple SYN packets to different ports from same source
        Flags: S=1, A=0 (SYN without ACK)
    ],
    
    'dns_tunneling': [
        Unusual DNS query patterns
        Large TXT records in DNS responses
    ],
    
    'data_exfiltration': [
        Large packets to external IPs
        Unusual protocols on standard ports
    ],
    
    'brute_force': [
        Multiple failed connection attempts
        High rate of connection resets
    ]
}
```

---

## 💾 Data Flow Diagram

```
┌─────────────┐
│ PCAP File   │
│ (*.pcap)    │
└──────┬──────┘
       │
       │ User clicks "Open PCAP File"
       │
       ▼
┌──────────────────┐
│  packet_parser   │
│  .load_pcap_file │
└────────┬─────────┘
         │
         │ Parses packets with Scapy
         │ Extracts info
         │ Calculates stats
         │
         ▼
  ┌─────────────────────┐
  │ packet_details[]    │
  │ protocol_stats{}    │
  │ ip_stats(src, dst)  │
  └────────┬────────────┘
           │
      ┌────┴─────────────┬─────────────────┐
      │                  │                 │
      ▼                  ▼                 ▼
┌────────────────┐  ┌──────────────┐  ┌─────────────┐
│  ui.py         │  │visualization │  │ ai_analysis │
│ Display table  │  │    .py       │  │    .py      │
│                │  │ Create charts│  │ Analyze     │
└────────────────┘  └──────────────┘  └─────────────┘
      │                  │                 │
      │                  │                 │
      ▼                  ▼                 ▼
  ┌────────────────────────────────────────────┐
  │        Main Window (Tkinter)               │
  │  ┌──────────────────────────────────────┐  │
  │  │  Packet Table (TreeView)             │  │
  │  │  + Selected Packet Details (Text)    │  │
  │  ├──────────────────────────────────────┤  │
  │  │  Charts (Matplotlib Canvas)          │  │
  │  │  + Pie, Line, Bar charts             │  │
  │  ├──────────────────────────────────────┤  │
  │  │  Analysis Report (ScrolledText)      │  │
  │  │  + Suspicious activity               │  │
  │  │  + Recommendations                   │  │
  │  └──────────────────────────────────────┘  │
  └────────────────────────────────────────────┘
```

---

## 🚀 How to Use the Application

### **Step 1: Install Dependencies**
```bash
pip install -r requirements.txt
```

### **Step 2: Run Application**
```bash
python3 main.py
```

### **Step 3: Load PCAP File**
- Click "📁 Open PCAP File" button
- Select `sample_traffic.pcap` or your own PCAP file
- Wait for parsing to complete

### **Step 4: View Traffic Analysis**
- Top panel: See visualization charts
- Left panel: Explore packet table, select packets for details
- Right panel: Click "🔍 Analyze Traffic" for AI insights

### **Step 5: Export Results**
- Click "📥 Export Report" to save analysis as text file

---

## 📊 Sample PCAP File Contents

The included `sample_traffic.pcap` contains **66 realistic packets**:

| Traffic Type | Count | Protocol | Ports |
|---|---|---|---|
| DNS Queries | 5 | UDP | 53 |
| HTTP | 20 | TCP | 80 |
| HTTPS | 6 | TCP | 443 |
| ICMP (Ping) | 8 | ICMP | N/A |
| NTP | 5 | UDP | 123 |
| SSH | 3 | TCP | 22 |
| Port Scan | 5 | TCP | Various |
| Data Transfer | 2 | TCP | 443 |
| **Total** | **66** | Mixed | Various |

---

## 🔄 Threading & Performance

The application uses threading to keep UI responsive:

```python
def _on_load_file(self):
    def load_in_background():
        # Time-consuming PCAP parsing
        self.parser.load_pcap_file(file_path)
        
        # Update UI in main thread
        self.root.after(0, self._populate_packet_table)
        self.root.after(0, self._update_visualizations)
        self.root.after(0, self._update_status, "Ready")
    
    # Run in background thread
    thread = threading.Thread(target=load_in_background, daemon=True)
    thread.start()
```

---

## 🔐 Error Handling

The application includes comprehensive error handling:

```python
try:
    # Load PCAP file
    self.parser.load_pcap_file(file_path)
except FileNotFoundError:
    messagebox.showerror("Error", "File not found")
except Exception as e:
    messagebox.showerror("Error", f"Failed to parse: {str(e)}")
    logger.error(f"PCAP parsing error: {e}")
```

---

## 🎯 Key Features Summary

| Feature | Module | Purpose |
|---|---|---|
| GUI Interface | ui.py | Display and user interaction |
| PCAP Parsing | packet_parser.py | Read network captures |
| Visualization | visualization.py | Charts and graphs |
| AI Analysis | ai_analysis.py | Traffic insights |
| Threading | ui.py | Non-blocking operations |
| Error Handling | All modules | Robust error reporting |
| Flexible Layout | ui.py | Resizable panels |
| Export | ui.py | Save reports |

---

## 📈 Future Enhancements

1. **API Integration**
   - OpenAI API for advanced threat analysis
   - VirusTotal API for IP/domain reputation

2. **Machine Learning**
   - Anomaly detection models
   - Traffic classification

3. **Live Capture**
   - Capture live traffic with tcpdump
   - Real-time monitoring

4. **Database Storage**
   - SQLite for persistent storage
   - Historical analysis

5. **Advanced Filtering**
   - BPF filters (like Wireshark)
   - Protocol-specific filtering

---

## 🛠️ Technical Stack

- **GUI Framework**: Tkinter (built-in Python)
- **Packet Analysis**: Scapy
- **Visualization**: Matplotlib
- **Language**: Python 3.8+
- **OS**: Linux, macOS, Windows

---

## 📝 Code Quality

- **Comments**: Extensive documentation
- **Type Hints**: Full type annotations
- **Logging**: Comprehensive logging setup
- **OOP**: Object-oriented design
- **Modularity**: Separated concerns
- **Error Handling**: Try-catch blocks

---

## ✅ Testing

Test with sample PCAP:
```bash
python3 main.py
# Load: sample_traffic.pcap
# Verify: All packets display, charts render, analysis generates
```

---

**Created**: 9 February 2026  
**Version**: 1.0  
**License**: MIT
