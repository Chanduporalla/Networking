# Sample Traffic PCAP File

## File: `sample_traffic.pcap`

This is a mid-level sample PCAP file with **66 realistic network packets** generated for testing the Network Traffic Analyzer application.

### Traffic Contents

The sample file includes various types of network traffic:

#### 1. **DNS Queries** (5 packets)
   - Queries to: google.com, github.com, stackoverflow.com, amazon.com, youtube.com
   - Protocol: UDP port 53
   - Purpose: Common legitimate network traffic

#### 2. **HTTP Traffic** (20+ packets)
   - TCP port 80 connections
   - Includes SYN, SYN-ACK, ACK handshakes
   - HTTP GET requests
   - Purpose: Simulate web browsing traffic

#### 3. **HTTPS/TLS Traffic** (6 packets)
   - TCP port 443 connections
   - TLS handshake simulation
   - Purpose: Encrypted web traffic

#### 4. **ICMP Echo (Ping)** (8 packets)
   - Echo requests and replies
   - Various source/destination pairs
   - Purpose: Diagnostics traffic

#### 5. **NTP/UDP Traffic** (5 packets)
   - UDP port 123
   - NTP (Network Time Protocol) packets
   - Purpose: Time synchronization traffic

#### 6. **SSH Traffic** (3 packets)
   - TCP port 22
   - SSH banner information
   - Purpose: Secure shell connections

#### 7. **Anomalous Traffic** (19+ packets)
   - **Port scanning**: SYN packets to ports 21, 22, 23, 25, 3389
   - **Suspicious connections**: Large data transfers
   - **Data exfiltration pattern**: Packets to external IPs (203.0.113.0/24)
   - Purpose: Test detection of suspicious activity

### How to Use

1. **Open the Network Traffic Analyzer application**
   ```bash
   python3 main.py
   ```

2. **Load the sample PCAP file**
   - Click "Upload PCAP File" button
   - Select `sample_traffic.pcap`
   - The application will parse all 66 packets

3. **Analyze the traffic**
   - View protocol distribution (TCP, UDP, ICMP)
   - Check packet details in the table
   - Click "Analyze Traffic" to see AI analysis
   - Look for detected suspicious patterns

### Key Metrics

- **Total Packets**: 66
- **File Size**: ~7.5 KB
- **Time Span**: ~3.3 seconds (50ms per packet)
- **Source IPs**: 192.168.1.0/24, 10.0.0.0/24
- **Destination IPs**: Various (Google, Cloudflare, YouTube, suspicious IPs)

### Protocol Distribution Expected

When loaded in the analyzer:
- **TCP**: ~50 packets (HTTP, HTTPS, SSH, Port Scan)
- **UDP**: ~10 packets (DNS, NTP)
- **ICMP**: ~8 packets (Ping)

### Anomalies to Detect

1. **Port Scan**: Multiple SYN packets from 192.168.1.105 to different ports
2. **Suspicious IPs**: Traffic to 203.0.113.0/24 (reserved for documentation)
3. **Large Packets**: 1400+ byte payloads on port 443
4. **Unusual Ports**: SSH connections to internal networks

### Regenerate Sample Traffic

If you want to create a new sample with different parameters:

```bash
python3 generate_sample_pcap.py
```

This will create a fresh `sample_traffic.pcap` with random variations while maintaining the same traffic patterns.

### Notes

- File uses real packet structures from Scapy library
- Timestamps are sequential (50ms intervals)
- IP addresses are realistic but use reserved/private ranges
- Suitable for testing and demonstration purposes
- Does not contain actual captured network traffic

---

**Created**: 9 February 2026  
**Generator**: generate_sample_pcap.py  
**Library**: Scapy 2.5+
