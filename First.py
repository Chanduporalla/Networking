import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import rdpcap
import textwrap

class NetworkVisualizer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Visualizer")
        self.geometry("1200x700")

        self.packets = []

        self.create_menu()
        self.create_packet_table()
        self.create_bottom_panes()

    def create_menu(self):
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=0)
        file_menu.add_command(label="Open PCAP", command=self.load_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        menu.add_cascade(label="File", menu=file_menu)
        self.config(menu=menu)

    def create_packet_table(self):
        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length")
        self.table = ttk.Treeview(self, columns=columns, show="headings", height=12)

        for col in columns:
            self.table.heading(col, text=col)
            self.table.column(col, anchor="center")

        self.table.pack(fill=tk.X)
        self.table.bind("<<TreeviewSelect>>", self.display_packet)

    def create_bottom_panes(self):
        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # RAW HEX VIEW
        left = tk.LabelFrame(paned, text="Raw Packet Bytes (HEX)")
        self.hex_view = tk.Text(left, font=("Consolas", 10))
        self.hex_view.pack(fill=tk.BOTH, expand=True)
        paned.add(left)

        # PACKET DETAILS VIEW
        right = tk.LabelFrame(paned, text="Packet Details (Decoded)")
        self.details = tk.Text(right, font=("Consolas", 10))
        self.details.pack(fill=tk.BOTH, expand=True)
        paned.add(right)

    def load_pcap(self):
        path = filedialog.askopenfilename(
            filetypes=[("PCAP Files", "*.pcap *.pcapng")]
        )
        if not path:
            return

        self.packets = rdpcap(path)
        self.table.delete(*self.table.get_children())

        for i, pkt in enumerate(self.packets, 1):
            src = pkt[0].src if hasattr(pkt[0], "src") else "N/A"
            dst = pkt[0].dst if hasattr(pkt[0], "dst") else "N/A"
            proto = pkt.lastlayer().name
            self.table.insert("", "end", iid=i-1,
                values=(i, f"{pkt.time:.6f}", src, dst, proto, len(pkt)))

    def display_packet(self, event):
        idx = int(self.table.selection()[0])
        pkt = self.packets[idx]

        # HEX
        raw = bytes(pkt)
        hex_dump = " ".join(f"{b:02X}" for b in raw)
        hex_dump = "\n".join(textwrap.wrap(hex_dump, 48))
        self.hex_view.delete("1.0", tk.END)
        self.hex_view.insert(tk.END, hex_dump)

        # DECODED
        self.details.delete("1.0", tk.END)
        for layer in pkt.layers():
            self.details.insert(tk.END, f"\n▶ {layer.__name__}\n")
            self.details.insert(tk.END, "-" * 40 + "\n")
            for field, value in pkt[layer].fields.items():
                self.details.insert(tk.END, f"{field:15}: {value}\n")


if __name__ == "__main__":
    NetworkVisualizer().mainloop()
