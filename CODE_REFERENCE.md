# Network Traffic Analyzer - Quick Reference Guide

## 📚 Main Code Components (Simple Overview)

### **1️⃣ main.py - START HERE**
**Purpose**: Launches the application  
**What it does**: Creates a Tkinter window and runs the app

```python
# This is the entry point - just run: python3 main.py
if __name__ == "__main__":
    main()
```

---

### **2️⃣ ui.py - GUI Interface**
**Purpose**: Creates the visual interface  
**What it does**: Manages buttons, windows, and displays data

#### Key Methods:
- `_build_ui()` - Creates layout (top, left, right panels)
- `_on_load_file()` - When user clicks "Open PCAP"
- `_on_packet_selected()` - When user clicks a packet
- `_on_analyze_traffic()` - When user clicks "Analyze"

#### The 3 Panel Layout:
```
┌─────────────────────────────┐
│     📊 Visualization        │ (Top - Graphs)
├──────────────┬──────────────┤
│   📋 Packet  │   🤖 AI      │ (Bottom - Split)
│   Details    │   Analysis   │
└──────────────┴──────────────┘
```

**Example Code:**
```python
class NetworkAnalyzerApp:
    def __init__(self, root):
        self.parser = PacketParser()      # Load packets
        self.visualizer = TrafficVisualizer()  # Make charts
        self.analyzer = AIAnalyzer()      # Analyze traffic
```

---

### **3️⃣ packet_parser.py - Read PCAP Files**
**Purpose**: Opens .pcap files and extracts packet information  
**What it does**: Uses Scapy library to parse network packets

#### Key Methods:
- `load_pcap_file(file_path)` - Opens the PCAP file
- `_parse_packets()` - Extracts all packet info
- `_extract_packet_info()` - Gets info from ONE packet

#### What Information is Extracted:
```python
packet_info = {
    'number': 1,              # Which packet (1st, 2nd, 3rd...)
    'timestamp': 1234567.89,  # When captured
    'src_ip': '192.168.1.1',  # From where
    'dst_ip': '8.8.8.8',      # To where
    'protocol': 'TCP',        # Type (TCP/UDP/DNS/ICMP)
    'src_port': 53892,        # Source port
    'dst_port': 53,           # Destination port
    'length': 68,             # Size in bytes
}
```

**Example Code:**
```python
parser = PacketParser()
parser.load_pcap_file('sample_traffic.pcap')

# Get statistics
print(parser.protocol_stats)   # {TCP: 35, UDP: 20, ...}
print(parser.source_ips)       # {192.168.1.1: 10, ...}
```

---

### **4️⃣ visualization.py - Make Charts**
**Purpose**: Creates graphs and visualizations  
**What it does**: Uses Matplotlib to draw charts

#### 3 Types of Charts:
1. **Pie Chart** - Shows protocol distribution (TCP %, UDP %, etc.)
2. **Line Chart** - Shows packets over time
3. **Bar Chart** - Shows top source/destination IPs

**Example Code:**
```python
visualizer = TrafficVisualizer()

# Create pie chart
canvas, fig, mpl_canvas = visualizer.create_protocol_distribution_chart(
    protocol_stats={'TCP': 35, 'UDP': 20, 'ICMP': 8},
    parent_frame=frame
)

# Embed in Tkinter window
canvas.pack(fill='both', expand=True)
```

---

### **5️⃣ ai_analysis.py - Analyze Traffic**
**Purpose**: Detects threats and provides insights  
**What it does**: Analyzes patterns and generates reports

#### Key Analysis Checks:
```
✓ Protocol Analysis
  └─ What protocols used? (TCP? UDP? DNS?)

✓ Traffic Patterns
  └─ Normal traffic or suspicious?

✓ Suspicious Activity
  └─ Port scans? Data exfiltration? Threats?

✓ IP Reputation
  └─ Are IPs from suspicious ranges?

✓ Recommendations
  └─ What should user do?
```

**Example Code:**
```python
analyzer = AIAnalyzer()
report = analyzer.analyze_traffic(
    packet_details=packets,
    protocol_stats={'TCP': 35, 'UDP': 20},
    ip_stats=(src_ips, dst_ips)
)

print(report)  # Beautiful formatted analysis
```

---

## 🔄 How Code Works Together

### **Flow When User Clicks "Open PCAP File":**

```
1. User clicks button in ui.py
   ↓
2. ui.py calls packet_parser.load_pcap_file()
   ↓
3. packet_parser reads PCAP file using Scapy
   ├─ Extracts each packet
   ├─ Gets IP, Protocol, Port info
   └─ Calculates statistics
   ↓
4. ui.py displays results:
   ├─ Fills packet table with packet_parser.packet_details
   ├─ Calls visualization to draw charts
   └─ Updates packet count display
```

### **Flow When User Clicks "Analyze Traffic":**

```
1. User clicks "🔍 Analyze Traffic" button in ui.py
   ↓
2. ui.py calls ai_analysis.analyze_traffic()
   ↓
3. ai_analysis.py checks traffic:
   ├─ Looks at all packets
   ├─ Checks for suspicious patterns
   ├─ Analyzes IP reputation
   └─ Generates recommendations
   ↓
4. ui.py displays report in right panel
```

---

## 📦 What Each Module Needs (Dependencies)

```
main.py:
├─ tkinter (built-in)
└─ ui.py

ui.py:
├─ tkinter (built-in)
├─ packet_parser.py
├─ visualization.py
└─ ai_analysis.py

packet_parser.py:
└─ scapy (pip install scapy)

visualization.py:
├─ matplotlib (pip install matplotlib)
└─ tkinter (built-in)

ai_analysis.py:
└─ (No external dependencies)
```

---

## 🧪 Testing Each Module Alone

### **Test packet_parser.py:**
```python
from packet_parser import PacketParser

parser = PacketParser()
parser.load_pcap_file('sample_traffic.pcap')

print(f"Total packets: {len(parser.packets)}")
print(f"Protocols: {parser.protocol_stats}")
print(f"First packet: {parser.packet_details[0]}")
```

### **Test visualization.py:**
```python
from visualization import TrafficVisualizer
from packet_parser import PacketParser
import tkinter as tk

parser = PacketParser()
parser.load_pcap_file('sample_traffic.pcap')

root = tk.Tk()
viz = TrafficVisualizer()
canvas, fig, _ = viz.create_protocol_distribution_chart(
    parser.protocol_stats,
    root
)
canvas.pack()
root.mainloop()
```

### **Test ai_analysis.py:**
```python
from ai_analysis import AIAnalyzer
from packet_parser import PacketParser

parser = PacketParser()
parser.load_pcap_file('sample_traffic.pcap')

analyzer = AIAnalyzer()
report = analyzer.analyze_traffic(
    parser.packet_details,
    parser.protocol_stats,
    (parser.source_ips, parser.dest_ips)
)

print(report)
```

---

## 🎯 Key Concepts Explained

### **PCAP File:**
- Binary file containing captured network packets
- Like a "recording" of network traffic
- Created by tcpdump, Wireshark, or other tools

### **Protocol:**
- Rules for communication (TCP, UDP, ICMP, DNS, HTTP, HTTPS, SSH, etc.)
- Packet tells you what protocol it uses

### **Port Number:**
- Identifies service on a computer (53=DNS, 80=HTTP, 443=HTTPS, 22=SSH)
- Helps identify what the packet is doing

### **IP Address:**
- Identifies computers (192.168.1.1, 8.8.8.8)
- Source IP = sending computer
- Destination IP = receiving computer

### **Suspicious Patterns:**
- **Port Scan**: SYN packets to many ports (trying to find open services)
- **Data Exfiltration**: Large packets to unknown IPs (stealing data)
- **Brute Force**: Many failed login attempts

---

## 🚀 Common Tasks

### **Task: Add a new chart type**
1. Go to `visualization.py`
2. Add new method like: `create_my_chart()`
3. Use Matplotlib to draw
4. Return canvas
5. Call from `ui.py` in `_update_visualizations()`

### **Task: Add a new detection rule**
1. Go to `ai_analysis.py`
2. Add check in `_check_suspicious_activity()`
3. Look for pattern in packets
4. Add to report

### **Task: Modify the layout**
1. Go to `ui.py`
2. Edit `_build_ui()` method
3. Change grid positions or sizes
4. Run app to see changes

### **Task: Support new protocol**
1. Go to `packet_parser.py`
2. Add to `_extract_packet_info()`
3. Check for new protocol using Scapy
4. Extract relevant fields

---

## 📊 Example: Complete Traffic Analysis

**Input**: sample_traffic.pcap (66 packets)

**Output**:
```
✓ 35 TCP packets (HTTP, HTTPS, SSH, Port Scan)
✓ 20 UDP packets (DNS, NTP)
✓ 8 ICMP packets (Ping)
✓ 3 ARP packets (Address Resolution)

🎯 Protocol Distribution:
  TCP: 53% (Web traffic, Secure Shell)
  UDP: 30% (DNS queries, NTP)
  ICMP: 12% (Network diagnostics)

⚠️  Suspicious Activity Found:
  1. Port scanning from 192.168.1.105
  2. Data transfer to 203.0.113.50
  3. Unusual DNS patterns

💡 Recommendations:
  - Block port scanner IP
  - Monitor external IP
  - Review DNS logs
```

---

## 🔍 Debugging Tips

### **If PCAP won't load:**
```python
# Check file exists
import os
print(os.path.exists('sample_traffic.pcap'))  # Should be True

# Try parsing with Scapy directly
from scapy.all import rdpcap
packets = rdpcap('sample_traffic.pcap')
print(len(packets))  # Should show 66
```

### **If charts don't display:**
```python
# Check Matplotlib backend
import matplotlib
print(matplotlib.get_backend())  # Should be 'TkAgg'

# Test figure creation
import matplotlib.pyplot as plt
fig = plt.figure()  # Should work without errors
```

### **If analysis is wrong:**
```python
# Print packet details to verify
from packet_parser import PacketParser
parser = PacketParser()
parser.load_pcap_file('sample_traffic.pcap')
print(parser.packet_details[0])  # Check first packet

# Print statistics
print(parser.protocol_stats)
print(parser.source_ips)
```

---

## 📚 Learning Path

**Beginner** → Start with `main.py` and `ui.py`  
**Intermediate** → Understand `packet_parser.py`  
**Advanced** → Modify `visualization.py` and `ai_analysis.py`  
**Expert** → Add new features and integrate APIs

---

**That's the complete project! All code is well-commented and modular.** 🎉
