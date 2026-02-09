"""
UI Module - Main Application Interface
Implements the Tkinter GUI with three-section layout:
- Top: Traffic Visualization Graphs
- Bottom-Left: Packet Details Table
- Bottom-Right: AI Analysis Panel
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import logging
from typing import Optional, Dict, List
from pathlib import Path

from packet_parser import PacketParser
from visualization import TrafficVisualizer
from ai_analysis import AIAnalyzer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkAnalyzerApp:
    """
    Main application GUI class for Network Traffic Analyzer.
    
    Layout:
    - Top half: Visualization panel (graphs)
    - Bottom half: Split between packet table (left) and AI analysis (right)
    
    Attributes:
        root: Tkinter root window
        parser: PacketParser instance
        visualizer: TrafficVisualizer instance
        analyzer: AIAnalyzer instance
    """
    
    def __init__(self, root: tk.Tk):
        """
        Initialize the Network Analyzer application.
        
        Args:
            root (tk.Tk): Tkinter root window
        """
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("1400x900")
        
        # Initialize components
        self.parser = PacketParser()
        self.visualizer = TrafficVisualizer()
        self.analyzer = AIAnalyzer()
        
        # State variables
        self.current_file = None
        self.canvas_widgets = {}  # Store canvas references
        self.analysis_performed = False
        
        # Configure root window
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Build the UI
        self._build_ui()
        
        logger.info("Network Traffic Analyzer initialized successfully")
    
    def _build_ui(self):
        """
        Build the main user interface layout with flexible/resizable panels.
        Creates all frames, widgets, and event bindings.
        Users can drag panel dividers to resize sections.
        """
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        main_frame.grid_rowconfigure(0, weight=0)  # Toolbar
        main_frame.grid_rowconfigure(1, weight=1)  # Paned window (flexible)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # === TOOLBAR ===
        self._build_toolbar(main_frame)
        
        # === FLEXIBLE LAYOUT WITH PANED WINDOWS ===
        # Vertical paned window (top and bottom sections)
        main_paned = tk.PanedWindow(main_frame, orient=tk.VERTICAL, 
                                     bd=2, sashwidth=5, sashpad=2)
        main_paned.grid(row=1, column=0, sticky='nsew')
        
        # === TOP SECTION: VISUALIZATION PANEL ===
        self.viz_frame = ttk.LabelFrame(
            main_paned,
            text="📊 Traffic Visualization (Drag to resize)",
            padding=10
        )
        main_paned.add(self.viz_frame, height=300)
        self.viz_frame.grid_rowconfigure(0, weight=1)
        self.viz_frame.grid_columnconfigure(0, weight=1)
        
        # Placeholder for visualization
        self.viz_placeholder = tk.Label(
            self.viz_frame,
            text="Load a PCAP file to display traffic visualizations",
            bg='#f0f0f0',
            fg='#666',
            font=('Arial', 11)
        )
        self.viz_placeholder.grid(row=0, column=0, sticky='nsew')
        
        # === BOTTOM SECTION: SPLIT INTO LEFT AND RIGHT (Horizontal Paned Window) ===
        bottom_container = tk.PanedWindow(main_paned, orient=tk.HORIZONTAL,
                                           bd=2, sashwidth=5, sashpad=2)
        main_paned.add(bottom_container, height=300)
        
        # === BOTTOM LEFT: PACKET DETAILS ===
        self.packet_frame = ttk.LabelFrame(
            bottom_container,
            text="📋 Packet Details (Drag to resize)",
            padding=10
        )
        bottom_container.add(self.packet_frame, width=700)
        self.packet_frame.grid_rowconfigure(1, weight=1)
        self.packet_frame.grid_columnconfigure(0, weight=1)
        self._build_packet_details_panel(self.packet_frame)
        
        # === BOTTOM RIGHT: AI ANALYSIS ===
        self.analysis_frame = ttk.LabelFrame(
            bottom_container,
            text="🤖 AI Traffic Analysis (Drag to resize)",
            padding=10
        )
        bottom_container.add(self.analysis_frame, width=700)
        self.analysis_frame.grid_rowconfigure(1, weight=1)
        self.analysis_frame.grid_columnconfigure(0, weight=1)
        self._build_ai_analysis_panel(self.analysis_frame)
    
    def _build_toolbar(self, parent: ttk.Frame):
        """
        Build the toolbar with file operations and controls.
        
        Args:
            parent: Parent frame
        """
        toolbar = ttk.Frame(parent)
        toolbar.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        
        # File selection button
        ttk.Button(
            toolbar,
            text="📁 Open PCAP File",
            command=self._on_load_file
        ).pack(side='left', padx=5)
        
        # File info label
        self.file_info_label = ttk.Label(
            toolbar,
            text="No file loaded",
            foreground='#666'
        )
        self.file_info_label.pack(side='left', padx=20)
        
        # Status label
        self.status_label = ttk.Label(
            toolbar,
            text="Ready",
            foreground='green'
        )
        self.status_label.pack(side='right', padx=5)
    
    def _build_packet_details_panel(self, parent: ttk.Frame):
        """
        Build the packet details table panel (bottom-left).
        
        Args:
            parent: Parent frame
        """
        # Statistics summary
        self.packet_stats_label = ttk.Label(
            parent,
            text="No packets loaded",
            font=('Arial', 9),
            foreground='#666'
        )
        self.packet_stats_label.grid(row=0, column=0, sticky='w', pady=(0, 5))
        
        # Create Treeview for packet table
        # Define columns
        columns = ('Packet #', 'Time', 'Source IP', 'Dest IP', 'Protocol', 'Length')
        self.packet_tree = ttk.Treeview(
            parent,
            columns=columns,
            height=15,
            show='headings',
            selectmode='browse'
        )
        
        # Define column headings and widths
        column_widths = {
            'Packet #': 60,
            'Time': 90,
            'Source IP': 120,
            'Dest IP': 120,
            'Protocol': 80,
            'Length': 70
        }
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=column_widths[col])
        
        # Add scrollbars
        scrollbar_y = ttk.Scrollbar(parent, orient='vertical', command=self.packet_tree.yview)
        scrollbar_x = ttk.Scrollbar(parent, orient='horizontal', command=self.packet_tree.xview)
        self.packet_tree.configure(yscroll=scrollbar_y.set, xscroll=scrollbar_x.set)
        
        # Bind selection event
        self.packet_tree.bind('<<TreeviewSelect>>', self._on_packet_selected)
        
        # Grid layout
        self.packet_tree.grid(row=1, column=0, sticky='nsew')
        scrollbar_y.grid(row=1, column=1, sticky='ns')
        scrollbar_x.grid(row=2, column=0, sticky='ew')
        
        # Packet detail information panel
        detail_frame = ttk.LabelFrame(
            parent,
            text="Selected Packet Details",
            padding=5
        )
        detail_frame.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(5, 0))
        
        self.packet_detail_text = scrolledtext.ScrolledText(
            detail_frame,
            height=4,
            width=80,
            font=('Courier', 9),
            wrap=tk.WORD
        )
        self.packet_detail_text.pack(fill='both', expand=True)
    
    def _build_ai_analysis_panel(self, parent: ttk.Frame):
        """
        Build the AI analysis panel (bottom-right).
        
        Args:
            parent: Parent frame
        """
        # Analyze button
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=0, column=0, sticky='ew', pady=(0, 5))
        
        ttk.Button(
            button_frame,
            text="🔍 Analyze Traffic",
            command=self._on_analyze_traffic
        ).pack(side='left', padx=5)
        
        ttk.Button(
            button_frame,
            text="📥 Export Report",
            command=self._on_export_report
        ).pack(side='left', padx=5)
        
        # Analysis results text area
        self.analysis_text = scrolledtext.ScrolledText(
            parent,
            font=('Courier', 9),
            wrap=tk.WORD,
            bg='#f5f5f5'
        )
        self.analysis_text.grid(row=1, column=0, sticky='nsew')
        
        # Insert placeholder
        placeholder = """Welcome to Network Traffic Analyzer!

Steps to analyze traffic:
1. Click "📁 Open PCAP File" to load a capture file
2. View packets in the packet details table
3. Check visualizations in the top panel
4. Click "🔍 Analyze Traffic" for AI-powered insights

The analysis will provide:
✓ Protocol distribution summary
✓ Traffic pattern detection
✓ Suspicious activity indicators
✓ Network recommendations
✓ IP reputation analysis

💡 TIP: Drag the panel dividers to resize sections to your preference!
"""
        self.analysis_text.insert('1.0', placeholder)
        self.analysis_text.config(state='disabled')
    
    # === EVENT HANDLERS ===
    
    def _on_load_file(self):
        """Handle file loading dialog and PCAP parsing."""
        file_path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[
                ("PCAP Files", "*.pcap;*.pcapng"),
                ("All Files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        # Load file in background thread to keep UI responsive
        self.status_label.config(text="Loading...", foreground='orange')
        self.root.update()
        
        thread = threading.Thread(
            target=self._load_pcap_file,
            args=(file_path,),
            daemon=True
        )
        thread.start()
    
    def _load_pcap_file(self, file_path: str):
        """
        Load and parse PCAP file in background thread.
        
        Args:
            file_path: Path to PCAP file
        """
        try:
            # Load PCAP file
            self.parser.load_pcap_file(file_path)
            self.current_file = file_path
            
            # Update UI in main thread
            self.root.after(0, self._update_ui_after_load)
            
        except Exception as e:
            error_msg = f"Error loading PCAP file: {str(e)}"
            logger.error(error_msg)
            self.root.after(
                0,
                lambda: messagebox.showerror("File Loading Error", error_msg)
            )
            self.root.after(0, lambda: self.status_label.config(text="Error", foreground='red'))
    
    def _update_ui_after_load(self):
        """Update UI after PCAP file is loaded."""
        try:
            # Update file info
            file_name = Path(self.current_file).name
            packet_count = self.parser.get_total_packet_count()
            data_volume = self.parser.get_total_data_volume()
            
            # Format data volume
            if data_volume < 1024:
                size_str = f"{data_volume} B"
            elif data_volume < 1024 ** 2:
                size_str = f"{data_volume / 1024:.2f} KB"
            else:
                size_str = f"{data_volume / (1024 ** 2):.2f} MB"
            
            self.file_info_label.config(
                text=f"{file_name} | {packet_count} packets | {size_str}",
                foreground='black'
            )
            
            # Clear existing visualization
            self._clear_visualization()
            
            # Update packet table
            self._populate_packet_table()
            
            # Create visualizations
            self._create_visualizations()
            
            # Update AI analysis placeholder
            self.analysis_text.config(state='normal')
            self.analysis_text.delete('1.0', 'end')
            self.analysis_text.insert(
                '1.0',
                "✓ PCAP file loaded successfully!\n\n"
                f"Packets loaded: {packet_count}\n"
                f"Data volume: {size_str}\n\n"
                "Click 'Analyze Traffic' to generate AI insights."
            )
            self.analysis_text.config(state='disabled')
            
            # Update status
            self.status_label.config(text="Ready", foreground='green')
            self.analysis_performed = False
            
        except Exception as e:
            logger.error(f"Error updating UI: {str(e)}")
            self.status_label.config(text="Error", foreground='red')
    
    def _clear_visualization(self):
        """Clear previous visualization from panel."""
        # Destroy previous widgets
        for widget in self.canvas_widgets.values():
            if isinstance(widget, tuple):
                # Tuple of (canvas_widget, fig, canvas)
                widget[0].destroy()
        self.canvas_widgets.clear()
        
        # Remove placeholder if exists
        if self.viz_placeholder.winfo_exists():
            self.viz_placeholder.grid_forget()
    
    def _create_visualizations(self):
        """Create and display traffic visualization graphs."""
        try:
            protocol_stats = self.parser.get_protocol_stats()
            timeline_data = self.parser.get_packet_timeline()
            src_ips, dst_ips = self.parser.get_ip_statistics()
            
            # Create combined visualization
            widget, fig, canvas = self.visualizer.create_combined_visualization(
                protocol_stats,
                timeline_data,
                self.viz_frame
            )
            
            if widget:
                widget.grid(row=0, column=0, sticky='nsew')
                self.canvas_widgets['combined'] = (widget, fig, canvas)
            
            logger.info("Visualizations created successfully")
            
        except Exception as e:
            logger.error(f"Error creating visualizations: {str(e)}")
            messagebox.showerror(
                "Visualization Error",
                f"Could not create visualizations: {str(e)}"
            )
    
    def _populate_packet_table(self):
        """Populate the packet details table with parsed packets."""
        try:
            # Clear existing items
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            
            # Get packet details
            packets = self.parser.get_packets()
            
            # Insert packets into table
            for packet in packets:
                self.packet_tree.insert(
                    '',
                    'end',
                    iid=packet['number'],
                    values=(
                        packet['number'],
                        packet['time_str'],
                        packet['src_ip'],
                        packet['dst_ip'],
                        packet['protocol'],
                        packet['length']
                    )
                )
            
            # Update statistics label
            total_packets = self.parser.get_total_packet_count()
            protocol_count = len(self.parser.get_protocol_stats())
            src_ips_count = len(self.parser.get_ip_statistics()[0])
            
            self.packet_stats_label.config(
                text=f"Total: {total_packets} packets | Protocols: {protocol_count} | Unique Sources: {src_ips_count}"
            )
            
            logger.info(f"Populated packet table with {total_packets} packets")
            
        except Exception as e:
            logger.error(f"Error populating packet table: {str(e)}")
            messagebox.showerror("Table Error", f"Error populating table: {str(e)}")
    
    def _on_packet_selected(self, event):
        """
        Handle packet selection from table.
        Displays detailed packet information.
        
        Args:
            event: Tkinter event object
        """
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        packet_num = int(selection[0])
        packet_info = self.parser.get_packet_by_number(packet_num)
        
        if not packet_info:
            return
        
        # Format detailed packet information
        detail_text = f"""
Packet #{packet_info['number']}
Time: {packet_info['time_str']}
─────────────────────────────────────────
Source:      {packet_info['src_ip']}:{packet_info['src_port']}
Destination: {packet_info['dst_ip']}:{packet_info['dst_port']}
Protocol:    {packet_info['protocol']}
Length:      {packet_info['length']} bytes
Info:        {packet_info['info']}
"""
        
        # Update detail text widget
        self.packet_detail_text.config(state='normal')
        self.packet_detail_text.delete('1.0', 'end')
        self.packet_detail_text.insert('1.0', detail_text)
        self.packet_detail_text.config(state='disabled')
    
    def _on_analyze_traffic(self):
        """Handle traffic analysis button click."""
        if not self.current_file:
            messagebox.showwarning(
                "No File Loaded",
                "Please load a PCAP file first."
            )
            return
        
        # Perform analysis in background thread
        self.status_label.config(text="Analyzing...", foreground='orange')
        self.root.update()
        
        thread = threading.Thread(
            target=self._perform_analysis,
            daemon=True
        )
        thread.start()
    
    def _perform_analysis(self):
        """Perform AI analysis on loaded packets."""
        try:
            packets = self.parser.get_packets()
            protocol_stats = self.parser.get_protocol_stats()
            ip_stats = self.parser.get_ip_statistics()
            
            # Get analysis results
            analysis_report = self.analyzer.analyze_traffic(
                packets,
                protocol_stats,
                ip_stats
            )
            
            # Update UI in main thread
            self.root.after(0, self._update_analysis_display, analysis_report)
            
        except Exception as e:
            error_msg = f"Error during analysis: {str(e)}"
            logger.error(error_msg)
            self.root.after(
                0,
                lambda: messagebox.showerror("Analysis Error", error_msg)
            )
        finally:
            self.root.after(0, lambda: self.status_label.config(text="Ready", foreground='green'))
    
    def _update_analysis_display(self, report: str):
        """
        Update the analysis text display.
        
        Args:
            report: Analysis report text
        """
        self.analysis_text.config(state='normal')
        self.analysis_text.delete('1.0', 'end')
        self.analysis_text.insert('1.0', report)
        self.analysis_text.config(state='disabled')
        self.analysis_performed = True
    
    def _on_export_report(self):
        """Export analysis report to file."""
        if not self.analysis_performed:
            messagebox.showwarning(
                "No Analysis",
                "Please perform analysis first."
            )
            return
        
        try:
            # Get current analysis text
            analysis_text = self.analysis_text.get('1.0', 'end')
            
            # Open save dialog
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[
                    ("Text Files", "*.txt"),
                    ("All Files", "*.*")
                ]
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(analysis_text)
                
                messagebox.showinfo(
                    "Success",
                    f"Report exported to:\n{file_path}"
                )
                logger.info(f"Report exported to {file_path}")
                
        except Exception as e:
            messagebox.showerror(
                "Export Error",
                f"Could not export report: {str(e)}"
            )
            logger.error(f"Error exporting report: {str(e)}")
