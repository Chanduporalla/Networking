# Network Traffic Analyzer - Desktop Application

A powerful desktop application for analyzing network traffic capture files (.pcap/.pcapng) with visual analytics and AI-powered traffic insights. Built with Python, Tkinter, and Scapy.

## Features

### 🎨 User Interface
- **Three-Section Layout:**
  - Top: Traffic Visualization Panel with interactive graphs
  - Bottom-Left: Packet Details Table with search and filter
  - Bottom-Right: AI Analysis Panel for traffic insights

### 📊 Visualizations
- **Protocol Distribution** - Pie chart showing protocol breakdown
- **Packet Timeline** - Line graph of packet count over time
- **Top IPs** - Bar charts for source/destination IP analysis
- **Traffic Statistics** - Comprehensive data volume analysis

### 🔍 Packet Analysis
- Parse PCAP/PCAPNG files with detailed packet extraction
- Display packet table with columns:
  - Packet Number
  - Timestamp
  - Source IP & Port
  - Destination IP & Port
  - Protocol
  - Packet Length
- Click on packets to view detailed hex/ASCII information
- Scrollable interface for large capture files

### 🤖 AI Analysis (Simulated, Ready for API Integration)
- **Traffic Pattern Detection:**
  - Unicast/Broadcast packet classification
  - Packet size distribution analysis
  - Average packet size calculation

- **Suspicious Activity Detection:**
  - Port scanning detection
  - DNS tunneling indicators
  - Worm/bot behavior patterns
  - Unusual port usage detection

- **Network Recommendations:**
  - Protocol-based optimization suggestions
  - Security recommendations
  - Bandwidth management insights

- **IP Reputation Analysis:**
  - Unique source/destination tracking
  - Top talkers identification
  - Ready for threat intelligence API integration

### 📁 File Management
- Load PCAP/PCAPNG files via file dialog
- Error handling for invalid files
- Status tracking and progress indicators
- Export analysis reports to text files

## System Requirements

- **Python:** 3.8 or higher
- **OS:** Windows, macOS, or Linux
- **RAM:** Minimum 2GB (4GB+ recommended for large captures)
- **Disk:** 100MB free space

## Installation

### 1. Clone or Download the Project

```bash
cd /path/to/CCNA&&CCNP/PROJECTS
```

### 2. Create Virtual Environment (Recommended)

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Required Packages

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install scapy matplotlib
```

### 4. Install Npcap (Windows Only)

For packet capture on Windows, install Npcap:
- Download from: https://npcap.com/download/
- Choose "Install Npcap in WinPcap API-compatible mode"

## Usage

### Running the Application

```bash
python main.py
```

Or directly:

```bash
python -m ui
```

### Basic Workflow

1. **Launch Application:** Click "Open PCAP File" button
2. **Select Capture File:** Choose a .pcap or .pcapng file from your system
3. **View Data:**
   - Check visualizations in top panel
   - Browse packets in bottom-left table
   - Click packets for detailed information
4. **Analyze Traffic:**
   - Click "Analyze Traffic" button
   - Review AI insights in bottom-right panel
5. **Export Results:**
   - Click "Export Report" to save analysis
   - Report exported as formatted text file

### Example PCAP Sources

- **Wireshark Samples:** https://wiki.wireshark.org/SampleCaptures
- **tcpdump captures** from your network
- **Network simulation captures** (Cisco Modeling Labs, GNS3)

## Project Structure

```
CCNA&&CCNP/PROJECTS/
│
├── main.py                 # Application entry point
├── ui.py                   # Main Tkinter GUI interface
├── packet_parser.py        # PCAP parsing logic
├── visualization.py        # Matplotlib chart generation
├── ai_analysis.py          # AI/analysis engine
│
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

### Module Descriptions

#### `main.py`
- Application entry point
- Initializes Tkinter root window
- Handles startup and error management

#### `ui.py` (≈550 lines)
- Main UI class: `NetworkAnalyzerApp`
- Manages three-panel layout
- Handles user interactions
- Threading for responsive UI
- File loading and packet display

#### `packet_parser.py` (≈250 lines)
- `PacketParser` class for PCAP parsing
- Uses Scapy library for packet extraction
- Protocol detection (TCP, UDP, DNS, ICMP, ARP)
- Statistics calculation
- Port and IP tracking

#### `visualization.py` (≈200 lines)
- `TrafficVisualizer` class
- Matplotlib integration
- Chart generation (pie, line, bar)
- Tkinter canvas embedding

#### `ai_analysis.py` (≈300 lines)
- `AIAnalyzer` class for traffic analysis
- Threat detection algorithms
- Report generation
- Structured output formatting

## Code Architecture

### Object-Oriented Design
- **PacketParser:** Handles all packet parsing and statistics
- **TrafficVisualizer:** Manages chart creation and updates
- **AIAnalyzer:** Performs analysis and generates insights
- **NetworkAnalyzerApp:** Coordinates GUI and components

### Threading Model
- UI thread: Tkinter event loop
- Background threads: File loading and analysis
- Thread-safe UI updates with `root.after()`

### Error Handling
- Try-except blocks for file operations
- Logging for debugging
- User-friendly error messages
- Graceful degradation for missing features

## Features for Network Engineers

### CCNA Level
- Protocol identification (TCP, UDP, ICMP, ARP, DNS)
- Source/destination analysis
- Basic traffic statistics
- Port number identification

### CCNP Level
- Traffic pattern analysis
- Suspicious activity detection
- Port scanning indicators
- DNS tunneling detection
- Connection behavior analysis

### Beyond Certifications
- Modular design for feature extension
- API-ready for threat intelligence integration
- Machine Learning placeholder for future enhancement
- Custom rule engine foundation

## Customization & Extension

### Adding New Protocols

Edit `packet_parser.py`, in `_extract_packet_info()`:

```python
elif CUSTOM_PROTOCOL in packet:
    packet_info['protocol'] = 'CUSTOM'
    # Extract custom data
```

### Integrating Real AI APIs

In `ai_analysis.py`, modify `_check_suspicious_activity()`:

```python
# Replace placeholder with actual API call
threat_score = call_threat_intelligence_api(ip_address)
```

### Custom Visualizations

Add methods to `visualization.py`:

```python
def create_custom_chart(self, data, parent_frame):
    fig = Figure(figsize=(10, 5), dpi=100)
    ax = fig.add_subplot(111)
    # Custom chart logic
```

## Performance Tips

- **Large Files:** For captures > 500MB, consider filtering with tcpdump first:
  ```bash
  tcpdump -r large.pcap -w filtered.pcap "tcp port 80"
  ```

- **Memory:** Monitor system resources when analyzing large captures
- **Responsive UI:** Analysis is done in background threads automatically

## Troubleshooting

### "ModuleNotFoundError: No module named 'scapy'"
```bash
pip install scapy
```

### "ImportError: No module named 'matplotlib'"
```bash
pip install matplotlib
```

### "Permission denied" on Linux
```bash
chmod +x main.py
```

### PCAP file not opening
- Verify file format (.pcap or .pcapng)
- Ensure file is not corrupted
- Check file permissions
- Try with sample file from Wireshark

### Visualization not showing
- Ensure matplotlib is installed
- Check for file system permissions
- Verify Tkinter is properly installed

## Future Enhancements

- [ ] Real-time packet capture and analysis
- [ ] Advanced filtering and search capabilities
- [ ] Integration with threat intelligence APIs
- [ ] Machine learning anomaly detection
- [ ] Custom rule engine for alert triggering
- [ ] Network flow analysis (NetFlow/sFlow)
- [ ] Multi-file comparison
- [ ] Dark mode UI theme
- [ ] Export to CSV/JSON formats
- [ ] Packet reconstruction and file carving

## Dependencies

| Package | Purpose | Min Version |
|---------|---------|-------------|
| scapy | Packet parsing | 2.4.5 |
| matplotlib | Visualization | 3.3.0 |
| tkinter | GUI (usually pre-installed) | - |

## License

MIT License - Feel free to use, modify, and distribute

## Contributing

Contributions welcome! Please:
1. Fork the project
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## Disclaimer

This tool is designed for:
- Network analysis on your own networks
- Educational and training purposes
- CCNA/CCNP study and certification preparation

Ensure you have permission before analyzing network traffic on systems you don't own.

## Author

Network Engineering Suite
Contact: [Your Contact Information]

## Support

For issues, questions, or suggestions:
1. Check this README thoroughly
2. Review error messages in application status bar
3. Check application logs in console output
4. Refer to Scapy and Matplotlib documentation

---

**Happy Network Analyzing! 🚀**
