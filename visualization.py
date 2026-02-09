"""
Visualization Module
Handles creation of traffic visualization graphs using Matplotlib.
Provides charts for protocol distribution, packet timeline, and traffic patterns.
"""

import matplotlib.pyplot as plt
import matplotlib
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import tkinter as tk
from typing import Dict, List, Tuple
import logging

# Use Tkinter-compatible backend
matplotlib.use('TkAgg')

logger = logging.getLogger(__name__)


class TrafficVisualizer:
    """
    Creates and manages traffic visualization charts.
    
    Attributes:
        figure: Matplotlib figure object
        canvas: Tkinter canvas for embedding plots
    """
    
    def __init__(self, parent_frame: tk.Frame = None):
        """
        Initialize the traffic visualizer.
        
        Args:
            parent_frame: Tkinter frame to embed visualizations
        """
        self.parent_frame = parent_frame
        self.figure = None
        self.canvas = None
        
    def create_protocol_distribution_chart(
        self, 
        protocol_stats: Dict[str, int],
        parent_frame: tk.Frame = None
    ) -> tk.Canvas:
        """
        Create a pie chart showing protocol distribution.
        
        Args:
            protocol_stats (Dict[str, int]): Protocol names and packet counts
            parent_frame (tk.Frame): Frame to embed the chart
            
        Returns:
            tk.Canvas: Tkinter canvas containing the chart
        """
        if parent_frame is None:
            parent_frame = self.parent_frame
            
        try:
            # Create figure with subplots
            fig = Figure(figsize=(5, 4), dpi=100)
            ax = fig.add_subplot(111)
            
            # Prepare data
            protocols = list(protocol_stats.keys())
            counts = list(protocol_stats.values())
            
            # Create pie chart
            colors = plt.cm.Set3(range(len(protocols)))
            ax.pie(
                counts,
                labels=protocols,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90
            )
            ax.set_title('Protocol Distribution', fontsize=12, fontweight='bold')
            
            # Embed in Tkinter
            canvas = FigureCanvasTkAgg(fig, master=parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget(), fig, canvas
            
        except Exception as e:
            logger.error(f"Error creating protocol distribution chart: {str(e)}")
            return None, None, None
    
    def create_packet_timeline_chart(
        self,
        timeline_data: List[Tuple[float, int]],
        parent_frame: tk.Frame = None
    ) -> tk.Canvas:
        """
        Create a line chart showing packet count over time.
        
        Args:
            timeline_data (List[Tuple[float, int]]): List of (timestamp, count) tuples
            parent_frame (tk.Frame): Frame to embed the chart
            
        Returns:
            tk.Canvas: Tkinter canvas containing the chart
        """
        if parent_frame is None:
            parent_frame = self.parent_frame
            
        try:
            # Create figure
            fig = Figure(figsize=(5, 4), dpi=100)
            ax = fig.add_subplot(111)
            
            # Prepare data
            if timeline_data:
                timestamps = [t[0] for t in timeline_data]
                packets = [t[1] for t in timeline_data]
                
                # Create line chart
                ax.plot(timestamps, packets, marker='o', linestyle='-', linewidth=2, markersize=4)
                ax.set_xlabel('Time (seconds)', fontsize=10)
                ax.set_ylabel('Packet Count', fontsize=10)
                ax.set_title('Packet Timeline', fontsize=12, fontweight='bold')
                ax.grid(True, alpha=0.3)
            else:
                ax.text(0.5, 0.5, 'No data available', ha='center', va='center')
                ax.set_title('Packet Timeline', fontsize=12, fontweight='bold')
            
            # Embed in Tkinter
            canvas = FigureCanvasTkAgg(fig, master=parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget(), fig, canvas
            
        except Exception as e:
            logger.error(f"Error creating packet timeline chart: {str(e)}")
            return None, None, None
    
    def create_top_ips_chart(
        self,
        ip_stats: Dict[str, int],
        chart_type: str = 'source',
        parent_frame: tk.Frame = None,
        limit: int = 10
    ) -> tk.Canvas:
        """
        Create a bar chart showing top source or destination IPs.
        
        Args:
            ip_stats (Dict[str, int]): IP addresses and packet counts
            chart_type (str): 'source' or 'destination'
            parent_frame (tk.Frame): Frame to embed the chart
            limit (int): Number of top IPs to display
            
        Returns:
            tk.Canvas: Tkinter canvas containing the chart
        """
        if parent_frame is None:
            parent_frame = self.parent_frame
            
        try:
            # Create figure
            fig = Figure(figsize=(5, 4), dpi=100)
            ax = fig.add_subplot(111)
            
            # Prepare data - get top N IPs
            if ip_stats:
                sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:limit]
                ips = [ip[0] for ip in sorted_ips]
                counts = [ip[1] for ip in sorted_ips]
                
                # Shorten IP labels if too long
                labels = [ip[:15] + '...' if len(ip) > 15 else ip for ip in ips]
                
                # Create bar chart
                ax.barh(labels, counts, color='steelblue')
                ax.set_xlabel('Packet Count', fontsize=10)
                ax.set_title(f'Top {chart_type.title()} IPs', fontsize=12, fontweight='bold')
                ax.invert_yaxis()
                
                # Add value labels on bars
                for i, v in enumerate(counts):
                    ax.text(v, i, f' {v}', va='center', fontsize=9)
            else:
                ax.text(0.5, 0.5, 'No data available', ha='center', va='center')
                ax.set_title(f'Top {chart_type.title()} IPs', fontsize=12, fontweight='bold')
            
            # Embed in Tkinter
            canvas = FigureCanvasTkAgg(fig, master=parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget(), fig, canvas
            
        except Exception as e:
            logger.error(f"Error creating IP statistics chart: {str(e)}")
            return None, None, None
    
    def create_combined_visualization(
        self,
        protocol_stats: Dict[str, int],
        timeline_data: List[Tuple[float, int]],
        parent_frame: tk.Frame = None
    ) -> Tuple:
        """
        Create a combined visualization with multiple charts.
        
        Args:
            protocol_stats (Dict[str, int]): Protocol statistics
            timeline_data (List[Tuple[float, int]]): Timeline data
            parent_frame (tk.Frame): Frame to embed charts
            
        Returns:
            Tuple: (canvas_widget, figure, canvas) for embedding
        """
        if parent_frame is None:
            parent_frame = self.parent_frame
            
        try:
            # Create figure with subplots
            fig = Figure(figsize=(10, 5), dpi=100)
            
            # Subplot 1: Protocol distribution (pie chart)
            ax1 = fig.add_subplot(121)
            if protocol_stats:
                protocols = list(protocol_stats.keys())
                counts = list(protocol_stats.values())
                colors = plt.cm.Set3(range(len(protocols)))
                ax1.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors, startangle=90)
            ax1.set_title('Protocol Distribution', fontsize=11, fontweight='bold')
            
            # Subplot 2: Packet timeline (line chart)
            ax2 = fig.add_subplot(122)
            if timeline_data:
                timestamps = [t[0] for t in timeline_data]
                packets = [t[1] for t in timeline_data]
                ax2.plot(timestamps, packets, marker='o', linestyle='-', linewidth=2, markersize=4, color='steelblue')
                ax2.set_xlabel('Time (seconds)', fontsize=9)
                ax2.set_ylabel('Packet Count', fontsize=9)
                ax2.grid(True, alpha=0.3)
            ax2.set_title('Packet Timeline', fontsize=11, fontweight='bold')
            
            fig.tight_layout()
            
            # Embed in Tkinter
            canvas = FigureCanvasTkAgg(fig, master=parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget(), fig, canvas
            
        except Exception as e:
            logger.error(f"Error creating combined visualization: {str(e)}")
            return None, None, None
