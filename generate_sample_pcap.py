#!/usr/bin/env python3
"""
Generate a sample PCAP file with realistic network traffic for testing.
This script creates various types of network packets including:
- TCP connections (HTTP, HTTPS)
- UDP traffic (DNS, NTP)
- ICMP (Ping)
"""

from scapy.all import wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from datetime import datetime, timedelta
import random

def generate_sample_pcap(filename="sample_traffic.pcap"):
    """
    Generate a sample PCAP file with various network traffic patterns.
    
    Args:
        filename (str): Output PCAP file name
    """
    
    packets = []
    base_time = datetime.now()
    
    # Source and destination IPs for realistic traffic
    src_ips = [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "10.0.0.50"
    ]
    
    dst_ips = [
        "8.8.8.8",           # Google DNS
        "1.1.1.1",           # Cloudflare DNS
        "142.251.32.14",     # Google
        "104.16.132.229",    # Cloudflare
        "172.217.16.142",    # YouTube
    ]
    
    packet_num = 0
    
    # 1. DNS Queries (UDP port 53)
    print("Generating DNS traffic...")
    dns_domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "amazon.com",
        "youtube.com"
    ]
    
    for i, domain in enumerate(dns_domains):
        packet_num += 1
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips[:2])  # Use DNS servers
        
        # DNS Query packet
        dns_pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(
            rd=1, 
            qd=DNSQR(qname=domain, qtype="A")
        )
        packets.append(dns_pkt)
    
    # 2. HTTP Traffic (TCP port 80)
    print("Generating HTTP traffic...")
    for i in range(8):
        packet_num += 1
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips[2:])  # Web servers
        src_port = random.randint(40000, 60000)
        
        # SYN packet
        syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=80, flags="S", seq=1000)
        packets.append(syn)
        
        # SYN-ACK packet (return)
        synack = IP(src=dst_ip, dst=src_ip) / TCP(sport=80, dport=src_port, flags="SA", seq=2000, ack=1001)
        packets.append(synack)
        
        # ACK packet
        ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=80, flags="A", seq=1001, ack=2001)
        packets.append(ack)
        
        # HTTP GET request
        http_payload = f"""GET / HTTP/1.1\r
Host: {dst_ips[2]}\r
User-Agent: Mozilla/5.0\r
Accept: text/html\r
Connection: close\r
\r
"""
        http_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=80, flags="A", seq=1001, ack=2001) / Raw(load=http_payload)
        packets.append(http_pkt)
    
    # 3. HTTPS Traffic (TCP port 443)
    print("Generating HTTPS traffic...")
    for i in range(6):
        packet_num += 1
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips[2:])
        src_port = random.randint(40000, 60000)
        
        # TLS/SSL Handshake (simplified)
        tls_data = b'\x16\x03\x01\x00\x50'  # TLS record header
        tls_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=443, flags="A") / Raw(load=tls_data)
        packets.append(tls_pkt)
    
    # 4. ICMP Echo (Ping)
    print("Generating ICMP traffic...")
    for i in range(4):
        packet_num += 1
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        
        # ICMP Echo Request
        icmp_req = IP(src=src_ip, dst=dst_ip) / ICMP(type="echo-request", id=1000+i)
        packets.append(icmp_req)
        
        # ICMP Echo Reply
        icmp_reply = IP(src=dst_ip, dst=src_ip) / ICMP(type="echo-reply", id=1000+i)
        packets.append(icmp_reply)
    
    # 5. UDP Traffic (NTP, port 123)
    print("Generating NTP/UDP traffic...")
    for i in range(5):
        packet_num += 1
        src_ip = random.choice(src_ips)
        dst_ip = "91.189.89.198"  # NTP Server
        
        ntp_payload = b'\x1b' + b'\x00' * 47  # Simplified NTP packet
        ntp_pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(40000, 60000), dport=123) / Raw(load=ntp_payload)
        packets.append(ntp_pkt)
    
    # 6. SSH Traffic (TCP port 22)
    print("Generating SSH traffic...")
    for i in range(3):
        packet_num += 1
        src_ip = random.choice(src_ips)
        dst_ip = "10.0.0.1"  # Internal server
        src_port = random.randint(40000, 60000)
        
        # SSH banner
        ssh_banner = b"SSH-2.0-OpenSSH_7.4\r\n"
        ssh_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=22) / Raw(load=ssh_banner)
        packets.append(ssh_pkt)
    
    # 7. Some suspicious/unusual traffic patterns
    print("Generating anomalous traffic...")
    
    # Port scanning pattern (SYN to multiple ports)
    for port in [21, 22, 23, 25, 3389]:
        packet_num += 1
        src_ip = "192.168.1.105"  # Suspicious source
        dst_ip = "192.168.1.1"
        scan_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(40000, 60000), dport=port, flags="S")
        packets.append(scan_pkt)
    
    # Large packet transfer (potential data exfiltration)
    for i in range(2):
        packet_num += 1
        src_ip = random.choice(src_ips)
        dst_ip = "203.0.113.50"  # External IP
        large_payload = b"A" * 1400  # Large payload
        large_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(40000, 60000), dport=443) / Raw(load=large_payload)
        packets.append(large_pkt)
    
    # 8. Set packet timestamps for realistic timing
    print("Setting packet timestamps...")
    for i, pkt in enumerate(packets):
        pkt.time = (base_time + timedelta(milliseconds=i*50)).timestamp()
    
    # Write to PCAP file
    print(f"Writing {len(packets)} packets to {filename}...")
    wrpcap(filename, packets)
    
    print(f"\n✓ Sample PCAP file generated successfully!")
    print(f"  Filename: {filename}")
    print(f"  Total packets: {len(packets)}")
    print(f"  Traffic types: DNS, HTTP, HTTPS, ICMP, NTP, SSH, Port Scan, Data Transfer")
    print(f"\nYou can now load this file in the Network Traffic Analyzer application.")


if __name__ == "__main__":
    try:
        generate_sample_pcap("sample_traffic.pcap")
    except ImportError:
        print("Error: Scapy is not installed.")
        print("Please install it with: pip install scapy")
    except Exception as e:
        print(f"Error generating PCAP file: {e}")
