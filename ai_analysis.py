"""
AI Analysis Module
Handles AI-powered network traffic analysis and anomaly detection.
Currently provides simulated analysis - ready for API integration.

Future Integration:
- OpenAI API for advanced threat analysis
- Machine Learning models for anomaly detection
- Custom rule engine for traffic classification
"""

import logging
from typing import Dict, List, Tuple
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    Performs AI and rule-based analysis on network traffic.
    Provides insights on traffic patterns, potential threats, and recommendations.
    
    Attributes:
        analysis_results: Dictionary storing analysis outputs
        suspicious_patterns: Known suspicious traffic patterns
    """
    
    def __init__(self):
        """Initialize the AI analyzer."""
        self.analysis_results = {}
        self.suspicious_patterns = {
            'port_scanning': [22, 23, 80, 443, 445, 3306, 5432, 27017],  # Common scan ports
            'suspicious_protocols': ['ICMP'],  # Often used in reconnaissance
            'high_port_range': range(49152, 65535),  # Ephemeral port range threshold
        }
    
    def analyze_traffic(
        self,
        packet_details: List[Dict],
        protocol_stats: Dict[str, int],
        ip_stats: Tuple[Dict, Dict]
    ) -> str:
        """
        Perform comprehensive analysis on network traffic.
        
        Args:
            packet_details (List[Dict]): List of parsed packet information
            protocol_stats (Dict[str, int]): Protocol distribution
            ip_stats (Tuple[Dict, Dict]): (source_ips, destination_ips) statistics
            
        Returns:
            str: Formatted analysis report
        """
        try:
            src_ips, dst_ips = ip_stats
            
            # Compile analysis results
            analysis = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_packets': len(packet_details),
                'total_data': self._calculate_total_data(packet_details),
                'protocol_analysis': self._analyze_protocols(protocol_stats),
                'traffic_patterns': self._detect_traffic_patterns(packet_details),
                'suspicious_indicators': self._check_suspicious_activity(packet_details, src_ips, dst_ips),
                'ip_reputation': self._analyze_ip_reputation(src_ips, dst_ips),
                'recommendations': self._generate_recommendations(protocol_stats, packet_details)
            }
            
            self.analysis_results = analysis
            return self._format_analysis_report(analysis)
            
        except Exception as e:
            logger.error(f"Error during traffic analysis: {str(e)}")
            return f"Error performing analysis: {str(e)}"
    
    def _calculate_total_data(self, packet_details: List[Dict]) -> str:
        """
        Calculate total data transferred.
        
        Args:
            packet_details: List of packet information
            
        Returns:
            str: Formatted data volume
        """
        total_bytes = sum(p['length'] for p in packet_details)
        
        # Convert to appropriate unit
        if total_bytes < 1024:
            return f"{total_bytes} B"
        elif total_bytes < 1024 ** 2:
            return f"{total_bytes / 1024:.2f} KB"
        elif total_bytes < 1024 ** 3:
            return f"{total_bytes / (1024 ** 2):.2f} MB"
        else:
            return f"{total_bytes / (1024 ** 3):.2f} GB"
    
    def _analyze_protocols(self, protocol_stats: Dict[str, int]) -> Dict:
        """
        Analyze protocol distribution and identify dominant protocols.
        
        Args:
            protocol_stats: Dictionary of protocol counts
            
        Returns:
            Dict: Protocol analysis results
        """
        if not protocol_stats:
            return {'top_protocols': [], 'protocol_count': 0}
        
        sorted_protocols = sorted(
            protocol_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            'top_protocols': [
                {'protocol': p[0], 'count': p[1], 'percentage': (p[1] / sum(protocol_stats.values()) * 100)}
                for p in sorted_protocols[:5]
            ],
            'protocol_count': len(protocol_stats),
            'dominant_protocol': sorted_protocols[0][0] if sorted_protocols else 'Unknown'
        }
    
    def _detect_traffic_patterns(self, packet_details: List[Dict]) -> Dict:
        """
        Detect traffic patterns and behavioral indicators.
        
        Args:
            packet_details: List of packet information
            
        Returns:
            Dict: Detected traffic patterns
        """
        patterns = {
            'unicast_packets': 0,
            'broadcast_packets': 0,
            'large_packets': 0,
            'small_packets': 0,
            'average_packet_size': 0
        }
        
        if not packet_details:
            return patterns
        
        for packet in packet_details:
            # Classify by packet size
            if packet['length'] > 1500:
                patterns['large_packets'] += 1
            elif packet['length'] < 60:
                patterns['small_packets'] += 1
            
            # Simple classification (more sophisticated in real implementation)
            if packet['dst_ip'].endswith('.255') or packet['dst_ip'] == 'N/A':
                patterns['broadcast_packets'] += 1
            else:
                patterns['unicast_packets'] += 1
        
        # Calculate average packet size
        total_size = sum(p['length'] for p in packet_details)
        patterns['average_packet_size'] = int(total_size / len(packet_details))
        
        return patterns
    
    def _check_suspicious_activity(
        self,
        packet_details: List[Dict],
        src_ips: Dict,
        dst_ips: Dict
    ) -> List[str]:
        """
        Check for suspicious network activity indicators.
        
        Args:
            packet_details: List of packet information
            src_ips: Source IP statistics
            dst_ips: Destination IP statistics
            
        Returns:
            List[str]: List of suspicious indicators found
        """
        suspicious = []
        
        # Check for port scanning behavior
        unique_dst_ports = set()
        for packet in packet_details:
            if packet['protocol'] == 'TCP' and packet['dst_port'] != 'N/A':
                unique_dst_ports.add(packet['dst_port'])
        
        if len(unique_dst_ports) > 100:
            suspicious.append(f"⚠️  Potential port scanning detected ({len(unique_dst_ports)} unique ports)")
        
        # Check for unusual port ranges
        high_ports = sum(1 for packet in packet_details 
                        if packet['protocol'] in ['TCP', 'UDP'] and 
                        packet['dst_port'] != 'N/A' and
                        packet['dst_port'] > 49152)
        
        if high_ports > len(packet_details) * 0.3:
            suspicious.append("⚠️  High percentage of traffic on ephemeral ports (possible P2P/malware)")
        
        # Check for DNS tunneling (DNS with unusual packet sizes)
        dns_large = sum(1 for packet in packet_details 
                       if packet['protocol'] == 'DNS' and packet['length'] > 512)
        
        if dns_large > 0:
            suspicious.append(f"⚠️  Suspicious DNS activity detected ({dns_large} large DNS packets)")
        
        # Check for connection attempts to multiple IPs (worm/bot behavior)
        if len(dst_ips) > 50 and len(packet_details) < 1000:
            suspicious.append(f"⚠️  Unusual connection pattern to {len(dst_ips)} different IPs")
        
        if not suspicious:
            suspicious.append("✓ No obvious suspicious indicators detected")
        
        return suspicious
    
    def _analyze_ip_reputation(self, src_ips: Dict, dst_ips: Dict) -> Dict:
        """
        Provide IP reputation analysis (placeholder for API integration).
        
        Args:
            src_ips: Source IP statistics
            dst_ips: Destination IP statistics
            
        Returns:
            Dict: IP reputation analysis
        """
        return {
            'unique_sources': len(src_ips),
            'unique_destinations': len(dst_ips),
            'top_source_ip': max(src_ips.items(), key=lambda x: x[1])[0] if src_ips else 'N/A',
            'top_destination_ip': max(dst_ips.items(), key=lambda x: x[1])[0] if dst_ips else 'N/A',
            'reputation_note': 'IP reputation checking requires integration with threat intelligence APIs'
        }
    
    def _generate_recommendations(
        self,
        protocol_stats: Dict[str, int],
        packet_details: List[Dict]
    ) -> List[str]:
        """
        Generate security and optimization recommendations.
        
        Args:
            protocol_stats: Protocol distribution
            packet_details: Packet details list
            
        Returns:
            List[str]: List of recommendations
        """
        recommendations = []
        
        # Protocol-based recommendations
        if 'UDP' in protocol_stats and protocol_stats['UDP'] > sum(protocol_stats.values()) * 0.5:
            recommendations.append("📌 High UDP traffic - consider bandwidth management policies")
        
        if 'DNS' in protocol_stats and protocol_stats['DNS'] > 100:
            recommendations.append("📌 High DNS queries - monitor for DNS exfiltration")
        
        # Traffic pattern recommendations
        if len(packet_details) > 0:
            avg_size = sum(p['length'] for p in packet_details) / len(packet_details)
            if avg_size > 1000:
                recommendations.append("📌 Large average packet size - may indicate bulk data transfer")
        
        # Default recommendation if none generated
        if not recommendations:
            recommendations.append("📌 Traffic appears normal - continue monitoring")
        
        return recommendations
    
    def _format_analysis_report(self, analysis: Dict) -> str:
        """
        Format analysis results into readable report.
        
        Args:
            analysis: Analysis results dictionary
            
        Returns:
            str: Formatted report text
        """
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║              NETWORK TRAFFIC ANALYSIS REPORT                     ║
╚══════════════════════════════════════════════════════════════════╝

📊 CAPTURE SUMMARY
─────────────────────────────────────────────────────────────────
  Timestamp:          {analysis['timestamp']}
  Total Packets:      {analysis['total_packets']}
  Total Data:         {analysis['total_data']}

🔍 PROTOCOL ANALYSIS
─────────────────────────────────────────────────────────────────
  Dominant Protocol:  {analysis['protocol_analysis']['dominant_protocol']}
  Unique Protocols:   {analysis['protocol_analysis']['protocol_count']}
"""
        
        # Add top protocols
        if analysis['protocol_analysis']['top_protocols']:
            report += "\n  Top Protocols:\n"
            for proto in analysis['protocol_analysis']['top_protocols']:
                report += f"    • {proto['protocol']}: {proto['count']} packets ({proto['percentage']:.1f}%)\n"
        
        # Add traffic patterns
        patterns = analysis['traffic_patterns']
        report += f"""
📈 TRAFFIC PATTERNS
─────────────────────────────────────────────────────────────────
  Average Packet Size: {patterns['average_packet_size']} bytes
  Unicast Packets:    {patterns['unicast_packets']}
  Broadcast Packets:  {patterns['broadcast_packets']}
  Large Packets:      {patterns['large_packets']}
  Small Packets:      {patterns['small_packets']}

🚨 SUSPICIOUS INDICATORS
─────────────────────────────────────────────────────────────────"""
        
        for indicator in analysis['suspicious_indicators']:
            report += f"\n  {indicator}"
        
        # Add IP reputation
        ip_rep = analysis['ip_reputation']
        report += f"""

🔗 IP STATISTICS
─────────────────────────────────────────────────────────────────
  Unique Source IPs:      {ip_rep['unique_sources']}
  Unique Dest IPs:        {ip_rep['unique_destinations']}
  Top Source IP:          {ip_rep['top_source_ip']}
  Top Destination IP:     {ip_rep['top_destination_ip']}

💡 RECOMMENDATIONS
─────────────────────────────────────────────────────────────────"""
        
        for i, rec in enumerate(analysis['recommendations'], 1):
            report += f"\n  {i}. {rec}"
        
        report += "\n\n" + "═" * 66 + "\n"
        
        return report
    
    def get_analysis_summary(self) -> str:
        """
        Get a summary of the last analysis performed.
        
        Returns:
            str: Summary text or empty string if no analysis done
        """
        if not self.analysis_results:
            return "No analysis performed yet. Load a PCAP file and click 'Analyze Traffic'."
        
        return self._format_analysis_report(self.analysis_results)
