# Network Traffic Analyzer - Architecture & Codebase Map

## 🏗️ Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER INTERFACE LAYER                         │
│                   (Tkinter - main.py, ui.py)                   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Main Application Window                       │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ TOOLBAR: [📁 Open PCAP]  File Info  [Status: Ready] │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │  VISUALIZATION PANEL (Matplotlib Canvas)              │  │ │
│  │  │  - Pie Chart (Protocol %)                             │  │ │
│  │  │  - Line Chart (Packets/Time)                          │  │ │
│  │  │  - Bar Chart (Top IPs)                                │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │  ┌────────────────────┬────────────────────────────────┐   │ │
│  │  │ PACKET TABLE       │ AI ANALYSIS                    │   │ │
│  │  │ (TreeView Widget)  │ (ScrolledText Widget)         │   │ │
│  │  │                    │                                │   │ │
│  │  │ Packet #, Time     │ [🔍 Analyze] [📥 Export]     │   │ │
│  │  │ Src IP, Dst IP     │                                │   │ │
│  │  │ Protocol, Length   │ Report Output:                 │   │ │
│  │  │                    │ - Protocols                    │   │ │
│  │  │ (Scrollable)       │ - Suspicious Activity          │   │ │
│  │  │                    │ - Recommendations              │   │ │
│  │  │ SELECTED PACKET    │                                │   │ │
│  │  │ DETAILS (Text)     │ (Scrollable, Exportable)      │   │ │
│  │  └────────────────────┴────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌──────────────────┐   ┌──────────────────┐  ┌──────────────────┐
│ PACKET PARSER    │   │ VISUALIZATION    │  │ AI ANALYSIS      │
│  LAYER           │   │ LAYER            │  │ LAYER            │
│                  │   │                  │  │                  │
│ packet_parser.py │   │visualization.py  │  │ ai_analysis.py   │
│                  │   │                  │  │                  │
│ • Load PCAP      │   │ • Pie Charts     │  │ • Analyze proto  │
│ • Parse packets  │   │ • Line Charts    │  │ • Detect threats │
│ • Extract info   │   │ • Bar Charts     │  │ • Create report  │
│ • Calculate      │   │ • Format data    │  │ • IP reputation  │
│   statistics     │   │   for display    │  │ • Recommend      │
└──────┬───────────┘   └────────┬─────────┘  └────────┬─────────┘
       │                        │                     │
       │                        │                     │
       └────────────────────────┼─────────────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │  DATA STRUCTURES       │
                    │                        │
                    │ packets[] - Raw Scapy  │
                    │ packet_details[]       │
                    │ protocol_stats{}       │
                    │ source_ips{}           │
                    │ dest_ips{}             │
                    │ analysis_results{}     │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │  DATA SOURCE LAYER     │
                    │                        │
                    │ sample_traffic.pcap    │
                    │ (66 network packets)   │
                    │                        │
                    │ Or user's own PCAP     │
                    └────────────────────────┘
```

---

## 📁 File Structure & Responsibilities

```
CCNA&&CCNP/PROJECTS/
│
├── 🟢 main.py (46 lines)
│   ├─ Purpose: Application entry point
│   ├─ Creates: Tkinter root window
│   ├─ Launches: NetworkAnalyzerApp
│   └─ Handles: Application-level errors
│
├── 🔵 ui.py (612 lines) ⭐ MAIN GUI MODULE
│   ├─ Class: NetworkAnalyzerApp
│   ├─ Methods:
│   │  ├─ __init__() - Initialize app
│   │  ├─ _build_ui() - Create layout
│   │  ├─ _build_toolbar() - Create toolbar
│   │  ├─ _build_packet_details_panel() - Left panel
│   │  ├─ _build_ai_analysis_panel() - Right panel
│   │  ├─ _on_load_file() - Load PCAP button
│   │  ├─ _on_packet_selected() - Packet selection
│   │  ├─ _on_analyze_traffic() - Analysis button
│   │  ├─ _on_export_report() - Export button
│   │  ├─ _update_visualizations() - Refresh charts
│   │  └─ _populate_packet_table() - Fill table
│   │
│   └─ Features:
│      ├─ Flexible/Resizable panels (PanedWindow)
│      ├─ File upload dialog
│      ├─ Real-time status updates
│      ├─ Threading for responsiveness
│      └─ Error handling with popups
│
├── 🟡 packet_parser.py (245 lines) ⭐ PACKET EXTRACTION
│   ├─ Class: PacketParser
│   ├─ Methods:
│   │  ├─ load_pcap_file() - Opens PCAP
│   │  ├─ _parse_packets() - Process all packets
│   │  ├─ _extract_packet_info() - Extract ONE packet
│   │  ├─ _update_statistics() - Update stats
│   │  ├─ get_protocol_statistics() - Return protocol stats
│   │  └─ get_ip_statistics() - Return IP stats
│   │
│   └─ Features:
│      ├─ Scapy-based PCAP reading
│      ├─ Protocol detection (TCP, UDP, ICMP, DNS, ARP)
│      ├─ Port extraction
│      ├─ Timestamp processing
│      ├─ IP address extraction
│      └─ Statistics calculation
│
├── 🟠 visualization.py (251 lines) ⭐ CHART GENERATION
│   ├─ Class: TrafficVisualizer
│   ├─ Methods:
│   │  ├─ create_protocol_distribution_chart() - Pie
│   │  ├─ create_packet_timeline_chart() - Line
│   │  ├─ create_top_ips_chart() - Bar
│   │  └─ create_combined_dashboard() - Multi-chart
│   │
│   └─ Features:
│      ├─ Matplotlib integration
│      ├─ Tkinter embedding (FigureCanvasTkAgg)
│      ├─ Multiple chart types
│      ├─ Color schemes
│      └─ Label formatting
│
├── 🔴 ai_analysis.py (358 lines) ⭐ ANALYSIS ENGINE
│   ├─ Class: AIAnalyzer
│   ├─ Methods:
│   │  ├─ analyze_traffic() - Main analysis
│   │  ├─ _analyze_protocols() - Protocol insights
│   │  ├─ _detect_traffic_patterns() - Pattern detection
│   │  ├─ _check_suspicious_activity() - Threat detection
│   │  ├─ _analyze_ip_reputation() - IP analysis
│   │  ├─ _generate_recommendations() - Suggestions
│   │  └─ _format_analysis_report() - Format output
│   │
│   └─ Features:
│      ├─ Protocol analysis
│      ├─ Traffic pattern detection
│      ├─ Suspicious activity detection
│      ├─ IP reputation checking
│      ├─ Recommendations generation
│      └─ Formatted report output
│
├── 🛠️ generate_sample_pcap.py (163 lines)
│   ├─ Purpose: Create test PCAP files
│   ├─ Generates:
│   │  ├─ DNS queries
│   │  ├─ HTTP traffic
│   │  ├─ HTTPS traffic
│   │  ├─ ICMP ping
│   │  ├─ NTP queries
│   │  ├─ SSH connections
│   │  └─ Suspicious patterns
│   └─ Output: sample_traffic.pcap (66 packets)
│
├── 📦 sample_traffic.pcap (7.5 KB)
│   └─ Real PCAP file with 66 network packets
│
├── 📄 requirements.txt
│   ├─ scapy==2.5.0
│   ├─ matplotlib==3.5.3
│   └─ (tkinter is built-in)
│
├── 📚 README.md
│   └─ Quick start guide
│
├── 📖 PROJECT_EXPLANATION.md ⭐ DETAILED GUIDE
│   └─ Complete project documentation
│
└── 📚 CODE_REFERENCE.md ⭐ THIS FILE
    └─ Quick reference and architecture
```

---

## 🔄 Data Flow: Complete Example

### **Scenario: User loads sample_traffic.pcap**

```
┌─────────────────────────────────────────────────────────────────┐
│ USER: Clicks "📁 Open PCAP File"                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │ ui.py: _on_load_file()               │
        │ - Shows file dialog                  │
        │ - User selects sample_traffic.pcap   │
        └──────────────────────┬───────────────┘
                               │
                               ▼
        ┌──────────────────────────────────────────┐
        │ packet_parser.py: load_pcap_file()       │
        │ - Opens file with Scapy: rdpcap()        │
        │ - Stores: self.packets = [...]           │
        │ - Calls: _parse_packets()                │
        └──────────────────────┬───────────────────┘
                               │
                               ▼
        ┌──────────────────────────────────────────┐
        │ packet_parser.py: _parse_packets()       │
        │ - Loops through 66 packets               │
        │ - For each: _extract_packet_info(p, idx) │
        │ - Builds: packet_details[] list          │
        │ - Collects: protocol_stats{}             │
        │ - Collects: source_ips{}, dest_ips{}     │
        └──────────────────────┬───────────────────┘
                               │
                               ▼
        ┌──────────────────────────────────────────┐
        │ Each packet extracted:                   │
        │                                          │
        │ packet = {                               │
        │   'number': 1,                           │
        │   'timestamp': 1234567.89,               │
        │   'src_ip': '192.168.1.100',             │
        │   'dst_ip': '8.8.8.8',                   │
        │   'protocol': 'UDP',                     │
        │   'src_port': 53892,                     │
        │   'dst_port': 53,  ← DNS port            │
        │   'length': 68,                          │
        │   'info': 'Query: google.com'            │
        │ }                                        │
        └──────────────────────┬───────────────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
                ▼              ▼              ▼
    ┌─────────────────┐ ┌──────────────┐  ┌──────────┐
    │ ui.py           │ │visualization │  │ Storage  │
    │ Populate table  │ │ Create charts│  │ Statistics
    │ Display packets │ │ Pie: Protocol│  │ protocols
    │                 │ │ Line: Time   │  │ source_ips
    │ 66 rows in      │ │ Bar: Top IPs │  │ dest_ips
    │ Treeview        │ │              │  │
    └────────┬────────┘ └──────┬───────┘  └──────────┘
             │                 │
             ▼                 ▼
    ┌─────────────────────────────────┐
    │ Main Window Updated with:        │
    │ • Packet table (sortable)        │
    │ • 3 charts (Protocol, Time, IPs) │
    │ • File info label                │
    │ • "Ready" status                 │
    └─────────────────────────────────┘
```

### **Scenario: User clicks "🔍 Analyze Traffic"**

```
┌────────────────────────────────────┐
│ USER: Clicks "🔍 Analyze Traffic"  │
└──────────────┬─────────────────────┘
               │
               ▼
    ┌──────────────────────────────┐
    │ ui.py: _on_analyze_traffic() │
    │ - Starts background thread   │
    │ - Shows "Analyzing..."       │
    └──────────────┬───────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────┐
    │ ai_analysis.py: analyze_traffic()         │
    │                                           │
    │ Passes:                                   │
    │ - packet_details[] (66 packets)          │
    │ - protocol_stats{} (TCP: 35, UDP: 20...) │
    │ - ip_stats (src_ips{}, dest_ips{})       │
    └──────────────┬──────────────────────────┘
                   │
        ┌──────────┼──────────┬──────────┐
        │          │          │          │
        ▼          ▼          ▼          ▼
    ┌──────┐  ┌────────┐ ┌──────────┐ ┌───────┐
    │Protocol
    │Analyze│  │Pattern │ │Suspicious│ │IP Rep │
    │       │  │Detect  │ │Activity  │ │Check  │
    └──────┘  └────────┘ └──────────┘ └───────┘
        │          │          │          │
        └──────────┼──────────┼──────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │ Analysis Results Dictionary:          │
    │ {                                     │
    │   'timestamp': '2026-02-09 14:30:45'  │
    │   'total_packets': 66,                │
    │   'protocol_analysis': {...},         │
    │   'traffic_patterns': {...},          │
    │   'suspicious_indicators': [...],     │
    │   'ip_reputation': {...},             │
    │   'recommendations': [...]            │
    │ }                                     │
    └──────────────┬───────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │ _format_analysis_report()             │
    │ - Converts dict to readable text      │
    │ - Adds emojis, sections, formatting   │
    │ - Returns: multi-line string          │
    └──────────────┬───────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │ ui.py: Display Report                 │
    │ - Updates right panel                 │
    │ - Shows in ScrolledText widget        │
    │ - Status changes to "Ready"           │
    └──────────────────────────────────────┘
```

---

## 🧩 Class Hierarchy

```
┌─────────────────────────────────────┐
│ PacketParser                        │
├─────────────────────────────────────┤
│ - packets: List[Packet]             │
│ - packet_details: List[Dict]        │
│ - protocol_stats: Dict[str, int]    │
│ - source_ips: Dict[str, int]        │
│ - dest_ips: Dict[str, int]          │
├─────────────────────────────────────┤
│ + load_pcap_file(path)              │
│ + get_protocol_statistics()         │
│ + get_ip_statistics()               │
│ + get_packet_details(num)           │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ TrafficVisualizer                   │
├─────────────────────────────────────┤
│ - parent_frame: tk.Frame            │
│ - figure: matplotlib.Figure         │
│ - canvas: FigureCanvasTkAgg         │
├─────────────────────────────────────┤
│ + create_protocol_distribution_chart│
│ + create_packet_timeline_chart()    │
│ + create_top_ips_chart()            │
│ + create_combined_dashboard()       │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ AIAnalyzer                          │
├─────────────────────────────────────┤
│ - analysis_results: Dict            │
│ - suspicious_patterns: Dict         │
├─────────────────────────────────────┤
│ + analyze_traffic(...)              │
│ + get_analysis_results()            │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ NetworkAnalyzerApp                  │
├─────────────────────────────────────┤
│ - root: tk.Tk                       │
│ - parser: PacketParser              │
│ - visualizer: TrafficVisualizer     │
│ - analyzer: AIAnalyzer              │
│ - packet_tree: ttk.Treeview         │
│ - analysis_text: ScrolledText       │
├─────────────────────────────────────┤
│ + _on_load_file()                   │
│ + _on_packet_selected()             │
│ + _on_analyze_traffic()             │
│ + _on_export_report()               │
└─────────────────────────────────────┘
```

---

## 🔌 How Modules Communicate

```
main.py
  │
  └─► Creates ─► tk.Tk() root
              └─► NetworkAnalyzerApp(root)
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
    packet_parser  visualization    ai_analysis
    PacketParser   TrafficVisualizer AIAnalyzer
        │               │               │
        │ Instance      │ Instance      │ Instance
        │               │               │
    Used by: ui.py ◄───────────────────┘
    
    NetworkAnalyzerApp creates instances of all 3:
    - self.parser = PacketParser()
    - self.visualizer = TrafficVisualizer()
    - self.analyzer = AIAnalyzer()
    
    When user clicks button:
    1. ui.py calls parser.load_pcap_file()
    2. parser returns packet_details
    3. ui.py calls visualizer.create_*_chart()
    4. visualizer returns canvas widget
    5. ui.py embeds canvas in frame
    
    When user clicks analyze:
    1. ui.py calls analyzer.analyze_traffic(
         packet_details,
         protocol_stats,
         ip_stats
       )
    2. analyzer returns formatted report string
    3. ui.py displays report in text widget
```

---

## 💾 Key Data Structures

### **packet_details List:**
```python
[
  {
    'number': 1,
    'timestamp': 1649123456.789,
    'time_str': '12:34:56.789',
    'src_ip': '192.168.1.100',
    'dst_ip': '8.8.8.8',
    'protocol': 'UDP',
    'src_port': 53892,
    'dst_port': 53,
    'length': 68,
    'info': 'Query: google.com',
    'raw_packet': <Scapy Packet object>
  },
  { ... packet 2 ... },
  { ... packet 3 ... },
  ...
]
```

### **protocol_stats Dict:**
```python
{
  'TCP': 35,
  'UDP': 20,
  'ICMP': 8,
  'ARP': 3
}
```

### **source_ips & dest_ips Dicts:**
```python
source_ips = {
  '192.168.1.100': 15,  # 15 packets from this IP
  '192.168.1.101': 12,
  '10.0.0.50': 8,
  ...
}

dest_ips = {
  '8.8.8.8': 20,        # 20 packets to this IP
  '1.1.1.1': 10,
  '142.251.32.14': 15,
  ...
}
```

---

## 🧪 Testing Strategy

```
Unit Tests (Test individual modules):
├─ packet_parser.py
│  └─ Load PCAP → Parse packets → Check results
├─ visualization.py
│  └─ Create charts → Check Matplotlib objects
└─ ai_analysis.py
   └─ Analyze traffic → Check report content

Integration Tests (Test modules together):
├─ Load PCAP
├─ Update UI with packet table
├─ Create visualizations
└─ Generate analysis report

System Tests (Full application):
├─ Launch main.py
├─ Load sample_traffic.pcap
├─ Interact with UI
├─ Verify all features work
└─ Check error handling
```

---

## 🚀 Execution Flow (Complete)

```
1. User types: python3 main.py
   └─► main() function runs
   
2. main.py:
   ├─ Creates: root = tk.Tk()
   ├─ Creates: app = NetworkAnalyzerApp(root)
   └─ Runs: root.mainloop()
   
3. NetworkAnalyzerApp.__init__(root):
   ├─ Initializes: self.parser = PacketParser()
   ├─ Initializes: self.visualizer = TrafficVisualizer()
   ├─ Initializes: self.analyzer = AIAnalyzer()
   └─ Calls: self._build_ui()
   
4. _build_ui():
   ├─ Creates: Main window layout
   ├─ Creates: Toolbar with buttons
   ├─ Creates: Visualization panel (empty)
   ├─ Creates: Packet table (empty)
   └─ Creates: Analysis panel (placeholder)
   
5. Tkinter event loop waits for user input
   
6. User clicks "📁 Open PCAP File":
   ├─ _on_load_file() triggered
   ├─ File dialog opens
   ├─ User selects file
   └─ _on_load_file() continues:
      ├─ Starts background thread
      ├─ Thread calls: parser.load_pcap_file(path)
      ├─ Parser extracts all packets
      ├─ Thread calls: _populate_packet_table()
      ├─ UI updates: Packet table filled
      ├─ Thread calls: _update_visualizations()
      ├─ UI updates: Charts displayed
      └─ Status: "Ready"
   
7. User clicks packet in table:
   ├─ _on_packet_selected() triggered
   └─ UI displays: Packet details in text widget
   
8. User clicks "🔍 Analyze Traffic":
   ├─ _on_analyze_traffic() triggered
   ├─ Starts background thread
   ├─ Thread calls: analyzer.analyze_traffic(...)
   ├─ Analyzer checks all patterns
   ├─ Analyzer returns formatted report
   ├─ UI updates: Report displayed in right panel
   └─ Status: "Ready"
   
9. User clicks "📥 Export Report":
   ├─ _on_export_report() triggered
   ├─ Save dialog opens
   ├─ User selects location
   └─ Report saved to file
   
10. User closes window:
    └─ root.mainloop() exits
    └─ Application stops
```

---

## 📊 Complexity Analysis

| Module | Lines | Complexity | Key Operations |
|--------|-------|-----------|-----------------|
| main.py | 46 | O(1) | Window creation |
| ui.py | 612 | O(n) | n = packet count |
| packet_parser.py | 245 | O(n) | n = packet count |
| visualization.py | 251 | O(n) | n = unique items |
| ai_analysis.py | 358 | O(n²) | n = packet count |
| **Total** | **~1500** | **Moderate** | **Scalable** |

*Note: Complexity assumes n packets to analyze*

---

**Complete Project Documentation** ✅  
**All components explained and mapped** ✅  
**Ready for understanding and extension** ✅
