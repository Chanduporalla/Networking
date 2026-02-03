import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from scapy.all import rdpcap
import textwrap

class PcapVisualizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Visualizer")
        self.root.geometry("1100x600")

        # Header
        tk.Label(
            root,
            text="🛜 Network Packet Visualizer (Wireshark-style)",
            font=("Consolas", 16, "bold")
        ).pack(pady=5)

        # Open button
        tk.Button(
            root,
            text="Open PCAP File",
            command=self.open_file,
            width=20
        ).pack(pady=5)

        # Packet list
        self.tree = ttk.Treeview(
            root,
            columns=("No", "Time", "Source", "Destination", "Protocol"),
            show="headings",
            height=8
        )
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        self.tree.pack(fill=tk.X, padx=10)
        self.tree.bind("<<TreeviewSelect>>", self.show_packet)

        # Split view
        paned = tk.PanedWindow(root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # LEFT → Raw data
        left_frame = tk.LabelFrame(paned, text="Raw Packet Data (HEX)")
        self.raw_text = tk.Text(left_frame, font=("Consolas", 10))
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        paned.add(left_frame)

        # RIGHT → Visual representation
        right_frame = tk.LabelFrame(paned, text="Decoded Packet View")
        self.decoded_text = tk.Text(right_frame, font=("Consolas", 10))
        self.decoded_text.pack(fill=tk.BOTH, expand=True)
        paned.add(right_frame)

        self.packets = []

    def open_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("PCAP Files", "*.pcap *.pcapng")]
        )
        if not file_path:
            return

        try:
            self.packets = rdpcap(file_path)
            self.tree.delete(*self.tree.get_children())

            for i, pkt in enumerate(self.packets, start=1):
                src = pkt[0].src if hasattr(pkt[0], "src") else "N/A"
                dst = pkt[0].dst if hasattr(pkt[0], "dst") else "N/A"
                proto = pkt.lastlayer().name

                self.tree.insert(
                    "", "end", iid=i-1,
                    values=(i, f"{pkt.time:.6f}", src, dst, proto)
                )

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_packet(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        pkt = self.packets[int(selected[0])]

        # RAW HEX VIEW
        raw_bytes = bytes(pkt)
        hex_dump = " ".join(f"{b:02X}" for b in raw_bytes)
        hex_dump = "\n".join(textwrap.wrap(hex_dump, 48))

        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert(tk.END, hex_dump)

        # DECODED VIEW
        decoded = ""
        for layer in pkt.layers():
            decoded += f"\n▶ {layer.__name__}\n"
            decoded += "-" * 40 + "\n"
            for field, value in pkt[layer].fields.items():
                decoded += f"{field:15}: {value}\n"

        self.decoded_text.delete("1.0", tk.END)
        self.decoded_text.insert(tk.END, decoded)


if __name__ == "__main__":
    root = tk.Tk()
    app = PcapVisualizer(root)
    root.mainloop()
