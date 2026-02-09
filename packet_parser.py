"""
Packet Parser Module
Handles reading and parsing PCAP/PCAPNG files using Scapy.
Extracts packet information and provides structured data for analysis.
"""

from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, ARP
from scapy.layers.inet import IP
import logging
from typing import List, Dict, Tuple
from datetime import datetime


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PacketParser:
    """
    Handles parsing of PCAP/PCAPNG files and extraction of packet details.
    
    Attributes:
        packets: List of parsed packets
        pcap_file: Path to the PCAP file
        packet_details: Detailed information for each packet
    """
    
    def __init__(self):
        """Initialize the packet parser."""
        self.packets = []
        self.pcap_file = None
        self.packet_details = []
        self.protocol_stats = {}
        self.source_ips = {}
        self.dest_ips = {}
        
    def load_pcap_file(self, file_path: str) -> bool:
        """
        Load and parse a PCAP/PCAPNG file.
        
        Args:
            file_path (str): Path to the PCAP file
            
        Returns:
            bool: True if successful, False otherwise
            
        Raises:
            Exception: If file cannot be read or parsed
        """
        try:
            # Validate file extension
            if not file_path.lower().endswith(('.pcap', '.pcapng')):
                raise ValueError("File must be a .pcap or .pcapng file")
            
            # Read PCAP file using Scapy
            self.packets = rdpcap(file_path)
            self.pcap_file = file_path
            
            # Parse all packets
            self._parse_packets()
            
            logger.info(f"Successfully loaded {len(self.packets)} packets from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading PCAP file: {str(e)}")
            raise
    
    def _parse_packets(self):
        """
        Parse all packets and extract relevant information.
        Populates packet_details, protocol_stats, and IP statistics.
        """
        self.packet_details = []
        self.protocol_stats = {}
        self.source_ips = {}
        self.dest_ips = {}
        
        for idx, packet in enumerate(self.packets, 1):
            packet_info = self._extract_packet_info(packet, idx)
            self.packet_details.append(packet_info)
            
            # Update statistics
            self._update_statistics(packet_info)
    
    def _extract_packet_info(self, packet, packet_num: int) -> Dict:
        """
        Extract detailed information from a single packet.
        
        Args:
            packet: Scapy packet object
            packet_num (int): Packet number in sequence
            
        Returns:
            Dict: Packet information containing key details
        """
        packet_info = {
            'number': packet_num,
            'timestamp': float(packet.time),
            'time_str': datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')[:-3],
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'protocol': 'Unknown',
            'length': len(packet),
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'info': '',
            'raw_packet': packet
        }
        
        # Extract IP information
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            # Determine protocol and extract port information
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['info'] = f"SYN={packet[TCP].flags.S}, ACK={packet[TCP].flags.A}"
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
                # Check for DNS traffic
                if DNS in packet:
                    packet_info['protocol'] = 'DNS'
                    if packet[DNS].qd:
                        packet_info['info'] = f"Query: {packet[DNS].qd.qname.decode('utf-8', errors='ignore')}"
                    
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"Type={packet[ICMP].type}, Code={packet[ICMP].code}"
                
        elif ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            packet_info['info'] = f"Op={packet[ARP].op}"
        
        return packet_info
    
    def _update_statistics(self, packet_info: Dict):
        """
        Update protocol and IP statistics.
        
        Args:
            packet_info (Dict): Parsed packet information
        """
        # Update protocol statistics
        protocol = packet_info['protocol']
        self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
        
        # Update source IP statistics
        src_ip = packet_info['src_ip']
        if src_ip != 'N/A':
            self.source_ips[src_ip] = self.source_ips.get(src_ip, 0) + 1
        
        # Update destination IP statistics
        dst_ip = packet_info['dst_ip']
        if dst_ip != 'N/A':
            self.dest_ips[dst_ip] = self.dest_ips.get(dst_ip, 0) + 1
    
    def get_packets(self) -> List[Dict]:
        """
        Get all parsed packet details.
        
        Returns:
            List[Dict]: List of packet information dictionaries
        """
        return self.packet_details
    
    def get_packet_by_number(self, packet_num: int) -> Dict:
        """
        Get detailed information for a specific packet.
        
        Args:
            packet_num (int): Packet number (1-indexed)
            
        Returns:
            Dict: Packet information
        """
        if 0 < packet_num <= len(self.packet_details):
            return self.packet_details[packet_num - 1]
        return None
    
    def get_protocol_stats(self) -> Dict[str, int]:
        """
        Get protocol distribution statistics.
        
        Returns:
            Dict[str, int]: Dictionary of protocol names and packet counts
        """
        return self.protocol_stats.copy()
    
    def get_ip_statistics(self) -> Tuple[Dict, Dict]:
        """
        Get source and destination IP statistics.
        
        Returns:
            Tuple[Dict, Dict]: Source IPs and destination IPs with counts
        """
        return self.source_ips.copy(), self.dest_ips.copy()
    
    def get_total_packet_count(self) -> int:
        """
        Get total number of packets parsed.
        
        Returns:
            int: Total packet count
        """
        return len(self.packet_details)
    
    def get_total_data_volume(self) -> int:
        """
        Get total data volume in bytes from all packets.
        
        Returns:
            int: Total bytes transferred
        """
        return sum(p['length'] for p in self.packet_details)
    
    def get_packet_timeline(self) -> List[Tuple[float, int]]:
        """
        Get packet count over time for timeline visualization.
        
        Returns:
            List[Tuple[float, int]]: List of (timestamp, packet_count) tuples
        """
        if not self.packet_details:
            return []
        
        # Create time buckets (1-second intervals)
        timeline = {}
        for packet in self.packet_details:
            time_bucket = int(packet['timestamp'])
            timeline[time_bucket] = timeline.get(time_bucket, 0) + 1
        
        # Sort by timestamp and return as list
        return sorted(timeline.items())
