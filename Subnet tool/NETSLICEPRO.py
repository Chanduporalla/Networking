#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        NETSLICE PRO — Industry-Level Subnetting Tool            ║
║        Dark Green Theme | GUI + Terminal Modes                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys
import ipaddress
import math
import argparse
import json
from typing import List, Tuple, Dict


# ─────────────────────────────────────────────
#  CORE SUBNET ENGINE
# ─────────────────────────────────────────────

class SubnetEngine:
    """Core subnetting calculations — no UI dependencies."""

    @staticmethod
    def parse_network(cidr: str) -> ipaddress.IPv4Network:
        try:
            return ipaddress.IPv4Network(cidr.strip(), strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid network: {e}")

    @staticmethod
    def network_info(cidr: str) -> Dict:
        net = SubnetEngine.parse_network(cidr)
        hosts = list(net.hosts())
        total_hosts = net.num_addresses
        if net.prefixlen == 32:
            usable = 1
        elif net.prefixlen == 31:
            usable = 2
        else:
            usable = max(0, total_hosts - 2)

        return {
            "network":      str(net.network_address),
            "broadcast":    str(net.broadcast_address),
            "mask":         str(net.netmask),
            "wildcard":     str(net.hostmask),
            "cidr":         f"/{net.prefixlen}",
            "prefix":       net.prefixlen,
            "total_hosts":  total_hosts,
            "usable_hosts": usable,
            "first_host":   str(hosts[0]) if hosts else str(net.network_address),
            "last_host":    str(hosts[-1]) if hosts else str(net.broadcast_address),
            "ip_class":     SubnetEngine.ip_class(str(net.network_address)),
            "ip_type":      SubnetEngine.ip_type(net),
            "binary_mask":  SubnetEngine.to_binary_mask(str(net.netmask)),
            "hex_mask":     SubnetEngine.to_hex(str(net.netmask)),
            "is_private":   net.is_private,
            "supernet":     str(net.supernet()) if net.prefixlen > 0 else "N/A",
        }

    @staticmethod
    def subnet_by_count(cidr: str, num_subnets: int) -> List[Dict]:
        if num_subnets < 1:
            raise ValueError("Number of subnets must be at least 1.")
        net = SubnetEngine.parse_network(cidr)
        bits_needed = math.ceil(math.log2(num_subnets)) if num_subnets > 1 else 1
        new_prefix = net.prefixlen + bits_needed
        if new_prefix > 30:
            raise ValueError(
                f"Cannot create {num_subnets} subnets from /{net.prefixlen} "
                f"(would need /{new_prefix}, max usable is /30)"
            )
        subnets = list(net.subnets(prefixlen_diff=bits_needed))
        return [SubnetEngine.network_info(str(s)) for s in subnets[:num_subnets]]

    @staticmethod
    def subnet_by_hosts(cidr: str, hosts_needed: int) -> Dict:
        if hosts_needed < 1:
            raise ValueError("Host count must be at least 1.")
        net = SubnetEngine.parse_network(cidr)
        bits = math.ceil(math.log2(hosts_needed + 2))
        new_prefix = 32 - bits
        if new_prefix < net.prefixlen:
            raise ValueError(
                f"Host count {hosts_needed} too large for /{net.prefixlen}. "
                f"Max usable hosts: {net.num_addresses - 2:,}"
            )
        new_net = ipaddress.IPv4Network(
            f"{net.network_address}/{new_prefix}", strict=False
        )
        return SubnetEngine.network_info(str(new_net))

    @staticmethod
    def vlsm(network: str, requirements: List[int]) -> List[Dict]:
        """Variable Length Subnet Masking — allocate by host requirements."""
        net = SubnetEngine.parse_network(network)
        reqs = sorted(requirements, reverse=True)
        results = []
        current_int = int(net.network_address)
        net_end_int = int(net.broadcast_address)

        for req in reqs:
            if req < 1:
                raise ValueError(f"Host requirement must be >= 1, got {req}")
            bits = math.ceil(math.log2(req + 2))
            prefix = 32 - bits
            block_size = 2 ** bits
            # Align to boundary
            if current_int % block_size != 0:
                current_int = ((current_int // block_size) + 1) * block_size
            if current_int > net_end_int:
                raise ValueError(
                    f"No space left in {network} to allocate {req} hosts."
                )
            candidate = ipaddress.IPv4Network(
                f"{ipaddress.IPv4Address(current_int)}/{prefix}", strict=True
            )
            if int(candidate.broadcast_address) > net_end_int:
                raise ValueError(
                    f"Subnet for {req} hosts ({candidate}) overflows {network}."
                )
            info = SubnetEngine.network_info(str(candidate))
            info["required_hosts"] = req
            results.append(info)
            current_int = int(candidate.broadcast_address) + 1

        return results

    @staticmethod
    def summarize(networks: List[str]) -> str:
        if not networks:
            raise ValueError("No networks provided.")
        nets = [ipaddress.IPv4Network(n.strip(), strict=False) for n in networks if n.strip()]
        return ", ".join(str(s) for s in ipaddress.collapse_addresses(nets))

    @staticmethod
    def check_overlap(networks: List[str]) -> List[Tuple[str, str]]:
        parsed = [(n.strip(), ipaddress.IPv4Network(n.strip(), strict=False))
                  for n in networks if n.strip()]
        return [
            (parsed[i][0], parsed[j][0])
            for i in range(len(parsed))
            for j in range(i + 1, len(parsed))
            if parsed[i][1].overlaps(parsed[j][1])
        ]

    @staticmethod
    def ip_in_subnet(ip: str, cidr: str) -> bool:
        return (ipaddress.IPv4Address(ip.strip())
                in ipaddress.IPv4Network(cidr.strip(), strict=False))

    @staticmethod
    def ip_class(ip: str) -> str:
        first = int(ip.split(".")[0])
        if first < 128:   return "A"
        elif first < 192: return "B"
        elif first < 224: return "C"
        elif first < 240: return "D (Multicast)"
        else:             return "E (Reserved)"

    @staticmethod
    def ip_type(net: ipaddress.IPv4Network) -> str:
        if net.is_loopback:   return "Loopback"
        if net.is_multicast:  return "Multicast"
        if net.is_private:    return "Private (RFC 1918)"
        if net.is_link_local: return "Link-Local"
        return "Public"

    @staticmethod
    def to_binary_mask(mask: str) -> str:
        return ".".join(f"{int(p):08b}" for p in mask.split("."))

    @staticmethod
    def to_hex(mask: str) -> str:
        return "0x" + "".join(f"{int(p):02X}" for p in mask.split("."))

    @staticmethod
    def reverse_dns(ip: str) -> str:
        return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"

    @staticmethod
    def ping_sweep_preview(cidr: str, limit: int = 20) -> List[str]:
        net = SubnetEngine.parse_network(cidr)
        return [str(h) for h in list(net.hosts())[:limit]]


# ─────────────────────────────────────────────
#  TERMINAL / CLI MODE
# ─────────────────────────────────────────────

class TerminalUI:
    GREEN  = "\033[92m"
    DGREEN = "\033[32m"
    CYAN   = "\033[96m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @classmethod
    def banner(cls):
        print(f"""
{cls.DGREEN}{cls.BOLD}
 ███╗   ██╗███████╗████████╗███████╗██╗     ██╗ ██████╗███████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██║██╔════╝██╔════╝
 ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║██║     █████╗
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║██║     ██╔══╝
 ██║ ╚████║███████╗   ██║   ███████║███████╗██║╚██████╗███████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝ ╚═════╝╚══════╝
{cls.GREEN}                  P R O  —  Industry Subnetting Tool{cls.RESET}
{cls.DIM}           Dark Green Edition  |  v2.1  |  IPv4{cls.RESET}
""")

    @classmethod
    def separator(cls, title=""):
        width = 70
        if title:
            pad = (width - len(title) - 2) // 2
            print(f"{cls.DGREEN}{'─'*pad} {cls.GREEN}{cls.BOLD}{title}{cls.RESET}{cls.DGREEN} {'─'*pad}{cls.RESET}")
        else:
            print(f"{cls.DGREEN}{'─'*width}{cls.RESET}")

    @classmethod
    def kv(cls, key: str, val: str, width: int = 22):
        print(f"  {cls.DGREEN}{key:<{width}}{cls.RESET} {cls.GREEN}{val}{cls.RESET}")

    @classmethod
    def print_network_info(cls, info: Dict, title="Network Information"):
        cls.separator(title)
        cls.kv("Network Address",  info["network"])
        cls.kv("Subnet Mask",      info["mask"])
        cls.kv("Wildcard Mask",    info["wildcard"])
        cls.kv("CIDR Notation",    info["cidr"])
        cls.kv("Broadcast",        info["broadcast"])
        cls.kv("First Host",       info["first_host"])
        cls.kv("Last Host",        info["last_host"])
        cls.kv("Total Addresses",  f"{info['total_hosts']:,}")
        cls.kv("Usable Hosts",     f"{info['usable_hosts']:,}")
        cls.kv("IP Class",         info["ip_class"])
        cls.kv("IP Type",          info["ip_type"])
        cls.kv("Binary Mask",      info["binary_mask"])
        cls.kv("Hex Mask",         info["hex_mask"])
        cls.kv("Supernet",         info["supernet"])
        cls.kv("Reverse DNS",      SubnetEngine.reverse_dns(info["network"]))
        cls.separator()

    @classmethod
    def interactive_menu(cls):
        cls.banner()
        while True:
            cls.separator("MAIN MENU")
            options = [
                ("1", "Network Info & Analysis"),
                ("2", "Subnet by Count"),
                ("3", "Subnet by Required Hosts"),
                ("4", "VLSM — Variable Length Subnet Masking"),
                ("5", "Route Summarization"),
                ("6", "Overlap Detection"),
                ("7", "IP-in-Subnet Check"),
                ("8", "Host List Preview"),
                ("Q", "Quit"),
            ]
            for k, v in options:
                print(f"  {cls.GREEN}[{cls.BOLD}{k}{cls.RESET}{cls.GREEN}]{cls.RESET}  {v}")
            cls.separator()
            choice = input(f"\n{cls.DGREEN}netslice{cls.RESET}{cls.GREEN}>{cls.RESET} ").strip().upper()
            try:
                if choice == "1":   cls._cmd_info()
                elif choice == "2": cls._cmd_subnet_count()
                elif choice == "3": cls._cmd_subnet_hosts()
                elif choice == "4": cls._cmd_vlsm()
                elif choice == "5": cls._cmd_summarize()
                elif choice == "6": cls._cmd_overlap()
                elif choice == "7": cls._cmd_ip_check()
                elif choice == "8": cls._cmd_host_list()
                elif choice == "Q":
                    print(f"\n{cls.GREEN}Goodbye. Stay secure.{cls.RESET}\n")
                    sys.exit(0)
                else:
                    print(f"{cls.RED}Invalid option.{cls.RESET}")
            except Exception as e:
                print(f"{cls.RED}Error: {e}{cls.RESET}")

    @classmethod
    def _prompt(cls, msg: str) -> str:
        return input(f"  {cls.CYAN}{msg}: {cls.RESET}").strip()

    @classmethod
    def _cmd_info(cls):
        info = SubnetEngine.network_info(cls._prompt("Enter CIDR (e.g. 192.168.1.0/24)"))
        cls.print_network_info(info)

    @classmethod
    def _cmd_subnet_count(cls):
        cidr = cls._prompt("Enter network CIDR")
        n    = int(cls._prompt("Number of subnets needed"))
        subnets = SubnetEngine.subnet_by_count(cidr, n)
        for i, s in enumerate(subnets, 1):
            cls.print_network_info(s, f"Subnet {i}/{len(subnets)}")
        print(f"{cls.GREEN}  Total: {len(subnets)} subnets{cls.RESET}")

    @classmethod
    def _cmd_subnet_hosts(cls):
        cidr  = cls._prompt("Enter network CIDR")
        hosts = int(cls._prompt("Hosts needed per subnet"))
        cls.print_network_info(SubnetEngine.subnet_by_hosts(cidr, hosts), f"Subnet for {hosts} hosts")

    @classmethod
    def _cmd_vlsm(cls):
        cidr = cls._prompt("Enter base network CIDR")
        raw  = cls._prompt("Host requirements (comma-sep, e.g. 50,30,10,2)")
        reqs = [int(x.strip()) for x in raw.split(",") if x.strip()]
        for i, s in enumerate(SubnetEngine.vlsm(cidr, reqs), 1):
            cls.print_network_info(s, f"VLSM Subnet {i} (need {s['required_hosts']} hosts)")

    @classmethod
    def _cmd_summarize(cls):
        raw  = cls._prompt("Enter networks (comma-sep)")
        nets = [n.strip() for n in raw.split(",") if n.strip()]
        cls.separator("Route Summary")
        print(f"  {cls.GREEN}Summary: {SubnetEngine.summarize(nets)}{cls.RESET}")
        cls.separator()

    @classmethod
    def _cmd_overlap(cls):
        raw  = cls._prompt("Enter networks (comma-sep)")
        nets = [n.strip() for n in raw.split(",") if n.strip()]
        overlaps = SubnetEngine.check_overlap(nets)
        cls.separator("Overlap Report")
        if overlaps:
            for a, b in overlaps:
                print(f"  {cls.RED}OVERLAP: {a}  ↔  {b}{cls.RESET}")
        else:
            print(f"  {cls.GREEN}No overlaps detected.{cls.RESET}")
        cls.separator()

    @classmethod
    def _cmd_ip_check(cls):
        ip   = cls._prompt("IP address")
        cidr = cls._prompt("Network CIDR")
        result = SubnetEngine.ip_in_subnet(ip, cidr)
        s = f"{cls.GREEN}✓ IN subnet" if result else f"{cls.RED}✗ NOT in subnet"
        print(f"\n  {s}  {ip} → {cidr}{cls.RESET}\n")

    @classmethod
    def _cmd_host_list(cls):
        cidr  = cls._prompt("Network CIDR")
        lstr  = cls._prompt("How many hosts to preview (max 254)")
        limit = int(lstr) if lstr else 20
        hosts = SubnetEngine.ping_sweep_preview(cidr, min(limit, 254))
        cls.separator(f"First {len(hosts)} Hosts")
        cols = 4
        for i in range(0, len(hosts), cols):
            row = hosts[i:i+cols]
            print("  " + "   ".join(f"{cls.GREEN}{h:<18}{cls.RESET}" for h in row))
        cls.separator()


# ─────────────────────────────────────────────
#  GUI MODE — Tkinter Dark Green Theme
# ─────────────────────────────────────────────

def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext
    except ImportError:
        print("tkinter not available. Use: python subnet_tool.py --cli")
        sys.exit(1)

    # ── Colour Palette ──
    BG       = "#0a0f0a"
    BG2      = "#0d150d"
    BG3      = "#111a11"
    PANEL    = "#0f1a0f"
    BORDER   = "#1a3a1a"
    GREEN    = "#00e676"
    GREEN2   = "#00c853"
    GREEN3   = "#69f0ae"
    DGREEN   = "#2e7d32"
    TEXT     = "#c8e6c9"
    TEXT_DIM = "#4caf50"
    RED      = "#ff5252"
    YELLOW   = "#ffd740"
    CYAN     = "#64ffda"

    FONT_MONO = ("Courier New", 10)
    FONT_MAIN = ("Consolas", 10)
    FONT_HEAD = ("Consolas", 12, "bold")
    FONT_TINY = ("Courier New", 9)

    root = tk.Tk()
    root.title("NetSlice Pro — Industry Subnetting Tool")
    root.geometry("1280x800")
    root.minsize(900, 600)
    root.configure(bg=BG)

    # ── ttk Style ──
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TNotebook",       background=BG2, borderwidth=0)
    style.configure("TNotebook.Tab",   background=BG3, foreground=TEXT_DIM,
                                       padding=[14, 6], font=FONT_MAIN)
    style.map("TNotebook.Tab",         background=[("selected", PANEL)],
                                       foreground=[("selected", GREEN)])
    style.configure("TFrame",          background=BG)
    style.configure("Treeview",        background=BG3, foreground=TEXT,
                                       fieldbackground=BG3, font=FONT_TINY, rowheight=22)
    style.configure("Treeview.Heading",background=DGREEN, foreground=GREEN,
                                       font=("Consolas", 9, "bold"))
    style.map("Treeview",              background=[("selected", DGREEN)],
                                       foreground=[("selected", GREEN)])
    style.configure("Vertical.TScrollbar",   background=BG3, troughcolor=BG2, arrowcolor=GREEN)
    style.configure("Horizontal.TScrollbar", background=BG3, troughcolor=BG2, arrowcolor=GREEN)

    # ── Widget helpers ──
    def styled_frame(parent, **kw):
        bg_ = kw.pop("bg", PANEL)
        return tk.Frame(parent, bg=bg_, highlightbackground=BORDER,
                        highlightthickness=1, **kw)

    def styled_entry(parent, width=30, **kw):
        e = tk.Entry(parent, bg=BG2, fg=GREEN, insertbackground=GREEN,
                     font=FONT_MONO, width=width, highlightbackground=BORDER,
                     highlightthickness=1, highlightcolor=GREEN, relief="flat", **kw)
        e.bind("<FocusIn>",  lambda ev: e.config(highlightbackground=GREEN))
        e.bind("<FocusOut>", lambda ev: e.config(highlightbackground=BORDER))
        return e

    def styled_button(parent, text, cmd, **kw):
        # FIX: pop padx/pady from kw before passing to Button to avoid
        #      'multiple values for keyword argument' TypeError
        px = kw.pop("padx", 12)
        py = kw.pop("pady", 5)
        b = tk.Button(parent, text=text, command=cmd,
                      bg=DGREEN, fg=GREEN, activebackground=GREEN2,
                      activeforeground=BG, font=FONT_MAIN,
                      relief="flat", cursor="hand2",
                      padx=px, pady=py, **kw)
        b.bind("<Enter>", lambda e: b.config(bg=GREEN2, fg=BG))
        b.bind("<Leave>", lambda e: b.config(bg=DGREEN, fg=GREEN))
        return b

    def styled_text(parent, h=18, w=80):
        t = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=TEXT, font=FONT_MONO,
            insertbackground=GREEN, height=h, width=w,
            highlightbackground=BORDER, highlightthickness=1,
            relief="flat", state="disabled",
            selectbackground=DGREEN, selectforeground=GREEN)
        t.tag_configure("head",  foreground=GREEN,   font=("Consolas", 10, "bold"))
        t.tag_configure("key",   foreground=TEXT_DIM)
        t.tag_configure("val",   foreground=GREEN3)
        t.tag_configure("error", foreground=RED)
        t.tag_configure("warn",  foreground=YELLOW)
        t.tag_configure("ok",    foreground=GREEN)
        t.tag_configure("sep",   foreground=DGREEN)
        t.tag_configure("cyan",  foreground=CYAN)
        return t

    def output_write(widget, lines):
        """
        FIX: Handles three item types correctly:
          ""            → blank line
          str           → plain text + newline
          (str, str)    → coloured (text, tag) + newline
        Previously kv_line() returned a list-of-tuples that was being
        appended as a single item — now net_info_lines emits flat pairs.
        """
        widget.config(state="normal")
        widget.delete("1.0", "end")
        for item in lines:
            if item == "":
                widget.insert("end", "\n")
            elif isinstance(item, str):
                widget.insert("end", item + "\n")
            else:
                widget.insert("end", item[0], item[1])
                widget.insert("end", "\n")
        widget.config(state="disabled")

    def sep_line():
        return ("─" * 64, "sep")

    def net_info_lines(info: Dict, title="") -> list:
        """
        FIX: Returns a flat list of (text, tag) tuples and "" separators.
        No longer uses kv_line() which returned a list-of-tuples causing
        output_write to treat each list as a single malformed item.
        """
        w = 24
        lines = []
        if title:
            lines.append((f"  ◆ {title}", "head"))
        lines.append(sep_line())
        pairs = [
            ("Network Address",  info["network"]),
            ("Subnet Mask",      info["mask"]),
            ("Wildcard Mask",    info["wildcard"]),
            ("CIDR Notation",    info["cidr"]),
            ("Broadcast",        info["broadcast"]),
            ("First Host",       info["first_host"]),
            ("Last Host",        info["last_host"]),
            ("Total Addresses",  f"{info['total_hosts']:,}"),
            ("Usable Hosts",     f"{info['usable_hosts']:,}"),
            ("IP Class",         info["ip_class"]),
            ("IP Type",          info["ip_type"]),
            ("Binary Mask",      info["binary_mask"]),
            ("Hex Mask",         info["hex_mask"]),
            ("Supernet",         info["supernet"]),
            ("Reverse DNS",      SubnetEngine.reverse_dns(info["network"])),
        ]
        for k, v in pairs:
            lines.append((f"  {k:<{w}}", "key"))
            lines.append((f"  {'':<{w}}{v}", "val"))
            lines.append("")
        lines.append(sep_line())
        return lines

    # ── Header ──
    header = tk.Frame(root, bg=BG2, height=56)
    header.pack(fill="x")
    header.pack_propagate(False)
    tk.Label(header, text="◈ NetSlice Pro", bg=BG2, fg=GREEN,
             font=("Consolas", 18, "bold")).pack(side="left", padx=20, pady=10)
    tk.Label(header, text="Industry-Grade IPv4 Subnetting Engine",
             bg=BG2, fg=TEXT_DIM, font=FONT_MAIN).pack(side="left", padx=8)
    tk.Label(header, text="Dark Green Edition", bg=BG2, fg=TEXT_DIM,
             font=FONT_TINY).pack(side="right", padx=8)
    tk.Label(header, text=" v2.1 ", bg=DGREEN, fg=GREEN,
             font=("Consolas", 9, "bold")).pack(side="right", padx=16, pady=18)

    # ── Notebook ──
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=(4, 8))

    # ══════════════════════════════════════════
    # TAB 1 — Network Info
    # ══════════════════════════════════════════
    tab1 = tk.Frame(nb, bg=BG)
    nb.add(tab1, text="  ◉ Network Info  ")

    top1 = styled_frame(tab1, bg=PANEL)
    top1.pack(fill="x", padx=10, pady=(10, 4))
    tk.Label(top1, text="Enter CIDR / IP:", bg=PANEL, fg=TEXT_DIM,
             font=FONT_MAIN).pack(side="left", padx=12, pady=10)
    e1_cidr = styled_entry(top1, width=28)
    e1_cidr.insert(0, "192.168.1.0/24")
    e1_cidr.pack(side="left", padx=8, pady=10)

    out1 = styled_text(tab1, h=28)
    out1.pack(fill="both", expand=True, padx=10, pady=4)

    def do_info():
        try:
            output_write(out1, net_info_lines(
                SubnetEngine.network_info(e1_cidr.get()),
                f"Analysis: {e1_cidr.get()}"
            ))
        except Exception as ex:
            output_write(out1, [(f"Error: {ex}", "error")])

    styled_button(top1, "  ▶  ANALYZE  ", do_info).pack(side="left", padx=8)

    # Quick presets — FIX: padx/pady go through kw; styled_button uses kw.pop()
    pf = tk.Frame(top1, bg=PANEL)
    pf.pack(side="left", padx=16)
    tk.Label(pf, text="Quick:", bg=PANEL, fg=TEXT_DIM, font=FONT_TINY).pack(side="left")
    for preset in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
        def _load(v=preset):
            e1_cidr.delete(0, "end")
            e1_cidr.insert(0, v)
            do_info()
        styled_button(pf, preset, _load, padx=6, pady=2).pack(side="left", padx=2)

    # ══════════════════════════════════════════
    # TAB 2 — Subnet Division
    # ══════════════════════════════════════════
    tab2 = tk.Frame(nb, bg=BG)
    nb.add(tab2, text="  ◉ Subnet Division  ")

    top2 = styled_frame(tab2, bg=PANEL)
    top2.pack(fill="x", padx=10, pady=(10, 4))
    tk.Label(top2, text="Network:", bg=PANEL, fg=TEXT_DIM,
             font=FONT_MAIN).pack(side="left", padx=10, pady=10)
    e2_net = styled_entry(top2, width=20)
    e2_net.insert(0, "10.0.0.0/16")
    e2_net.pack(side="left", padx=4, pady=10)
    tk.Label(top2, text="Subnets:", bg=PANEL, fg=TEXT_DIM,
             font=FONT_MAIN).pack(side="left", padx=8)
    e2_count = styled_entry(top2, width=6)
    e2_count.insert(0, "4")
    e2_count.pack(side="left", padx=4)

    tree2_f = tk.Frame(tab2, bg=BG)
    tree2_f.pack(fill="both", expand=True, padx=10, pady=4)
    cols2 = ["#", "Network", "Mask", "Broadcast", "First Host", "Last Host", "Usable Hosts", "CIDR"]
    tree2 = ttk.Treeview(tree2_f, columns=cols2, show="headings")
    for c in cols2:
        tree2.heading(c, text=c)
        tree2.column(c, width=50 if c in ("#", "CIDR") else 130, anchor="w")
    sb2  = ttk.Scrollbar(tree2_f, orient="vertical",   command=tree2.yview)
    sb2h = ttk.Scrollbar(tree2_f, orient="horizontal", command=tree2.xview)
    tree2.configure(yscrollcommand=sb2.set, xscrollcommand=sb2h.set)
    sb2.pack(side="right",  fill="y")
    sb2h.pack(side="bottom", fill="x")
    tree2.pack(fill="both", expand=True)
    status2 = tk.Label(tab2, text="", bg=BG, fg=GREEN, font=FONT_MAIN)
    status2.pack(pady=4)

    def do_subnet_div():
        for r in tree2.get_children(): tree2.delete(r)
        try:
            subnets = SubnetEngine.subnet_by_count(e2_net.get(), int(e2_count.get()))
            for i, s in enumerate(subnets, 1):
                tree2.insert("", "end", values=(
                    i, s["network"], s["mask"], s["broadcast"],
                    s["first_host"], s["last_host"],
                    f"{s['usable_hosts']:,}", s["cidr"]
                ))
            status2.config(text=f"✓  {len(subnets)} subnets from {e2_net.get()}", fg=GREEN)
        except Exception as ex:
            status2.config(text=f"✗  {ex}", fg=RED)

    styled_button(top2, "  ▶  DIVIDE  ", do_subnet_div).pack(side="left", padx=10)

    # ══════════════════════════════════════════
    # TAB 3 — By Host Count
    # ══════════════════════════════════════════
    tab3 = tk.Frame(nb, bg=BG)
    nb.add(tab3, text="  ◉ By Host Count  ")

    top3 = styled_frame(tab3, bg=PANEL)
    top3.pack(fill="x", padx=10, pady=(10, 4))
    tk.Label(top3, text="Base Network:", bg=PANEL, fg=TEXT_DIM,
             font=FONT_MAIN).pack(side="left", padx=10, pady=10)
    e3_net = styled_entry(top3, width=20)
    e3_net.insert(0, "192.168.10.0/24")
    e3_net.pack(side="left", padx=4)
    tk.Label(top3, text="Hosts needed:", bg=PANEL, fg=TEXT_DIM,
             font=FONT_MAIN).pack(side="left", padx=8)
    e3_hosts = styled_entry(top3, width=8)
    e3_hosts.insert(0, "50")
    e3_hosts.pack(side="left", padx=4)

    out3 = styled_text(tab3, h=28)
    out3.pack(fill="both", expand=True, padx=10, pady=4)

    def do_by_hosts():
        try:
            h = int(e3_hosts.get())
            output_write(out3, net_info_lines(
                SubnetEngine.subnet_by_hosts(e3_net.get(), h),
                f"Subnet for {h} hosts"
            ))
        except Exception as ex:
            output_write(out3, [(f"Error: {ex}", "error")])

    styled_button(top3, "  ▶  CALCULATE  ", do_by_hosts).pack(side="left", padx=10)

    # ══════════════════════════════════════════
    # TAB 4 — VLSM
    # ══════════════════════════════════════════
    tab4 = tk.Frame(nb, bg=BG)
    nb.add(tab4, text="  ◉ VLSM  ")

    top4 = styled_frame(tab4, bg=PANEL)
    top4.pack(fill="x", padx=10, pady=(10, 4))
    tk.Label(top4, text="Base Network:", bg=PANEL, fg=TEXT_DIM,
             font=FONT_MAIN).pack(side="left", padx=10, pady=10)
    e4_net = styled_entry(top4, width=20)
    e4_net.insert(0, "10.10.0.0/20")
    e4_net.pack(side="left", padx=4)
    tk.Label(top4, text="Host Requirements (comma-sep):", bg=PANEL, fg=TEXT_DIM,
             font=FONT_MAIN).pack(side="left", padx=8)
    e4_reqs = styled_entry(top4, width=30)
    e4_reqs.insert(0, "100, 60, 30, 10, 2")
    e4_reqs.pack(side="left", padx=4)

    cols4 = ["Req. Hosts", "Network", "Mask", "CIDR", "Broadcast",
             "First Host", "Last Host", "Usable", "Type"]
    tree4_f = tk.Frame(tab4, bg=BG)
    tree4_f.pack(fill="both", expand=True, padx=10, pady=4)
    tree4 = ttk.Treeview(tree4_f, columns=cols4, show="headings")
    for c in cols4:
        tree4.heading(c, text=c)
        tree4.column(c, width=110, anchor="w")
    sb4 = ttk.Scrollbar(tree4_f, orient="vertical", command=tree4.yview)
    tree4.configure(yscrollcommand=sb4.set)
    sb4.pack(side="right", fill="y")
    tree4.pack(fill="both", expand=True)
    status4 = tk.Label(tab4, text="", bg=BG, fg=GREEN, font=FONT_MAIN)
    status4.pack(pady=4)

    def do_vlsm():
        for r in tree4.get_children(): tree4.delete(r)
        try:
            reqs = [int(x.strip()) for x in e4_reqs.get().split(",") if x.strip()]
            subnets = SubnetEngine.vlsm(e4_net.get(), reqs)
            for s in subnets:
                tree4.insert("", "end", values=(
                    s["required_hosts"], s["network"], s["mask"], s["cidr"],
                    s["broadcast"], s["first_host"], s["last_host"],
                    f"{s['usable_hosts']:,}", s["ip_type"]
                ))
            status4.config(text=f"✓  VLSM complete — {len(subnets)} subnets", fg=GREEN)
        except Exception as ex:
            status4.config(text=f"✗  {ex}", fg=RED)

    styled_button(top4, "  ▶  ALLOCATE  ", do_vlsm).pack(side="left", padx=10)

    # ══════════════════════════════════════════
    # TAB 5 — Utilities
    # ══════════════════════════════════════════
    tab5 = tk.Frame(nb, bg=BG)
    nb.add(tab5, text="  ◉ Utilities  ")

    util_left  = tk.Frame(tab5, bg=BG)
    util_left.pack(side="left", fill="both", expand=True, padx=4, pady=8)
    util_right = tk.Frame(tab5, bg=BG)
    util_right.pack(side="left", fill="both", expand=True, padx=4, pady=8)

    # Route Summarization
    sum_f = styled_frame(util_left, bg=PANEL)
    sum_f.pack(fill="x", pady=4)
    tk.Label(sum_f, text="◈ Route Summarization", bg=PANEL, fg=GREEN,
             font=FONT_HEAD).pack(anchor="w", padx=12, pady=(10, 4))
    tk.Label(sum_f, text="Networks (one per line or comma-sep):", bg=PANEL,
             fg=TEXT_DIM, font=FONT_TINY).pack(anchor="w", padx=12)
    e5_sum = tk.Text(sum_f, bg=BG2, fg=GREEN, font=FONT_MONO, height=5, width=35,
                     highlightbackground=BORDER, highlightthickness=1,
                     relief="flat", insertbackground=GREEN)
    e5_sum.insert("end", "192.168.0.0/24\n192.168.1.0/24\n192.168.2.0/24\n192.168.3.0/24")
    e5_sum.pack(padx=12, pady=4)
    sum_result = tk.Label(sum_f, text="", bg=PANEL, fg=CYAN, font=FONT_MONO,
                          wraplength=320, justify="left")
    sum_result.pack(padx=12, pady=4)

    def do_summarize():
        raw  = e5_sum.get("1.0", "end").replace(",", "\n")
        nets = [n.strip() for n in raw.splitlines() if n.strip()]
        try:
            sum_result.config(text=f"Summary: {SubnetEngine.summarize(nets)}", fg=CYAN)
        except Exception as ex:
            sum_result.config(text=str(ex), fg=RED)

    styled_button(sum_f, "  ▶  SUMMARIZE  ", do_summarize).pack(pady=(0, 10))

    # Overlap Detection
    ovlp_f = styled_frame(util_left, bg=PANEL)
    ovlp_f.pack(fill="x", pady=4)
    tk.Label(ovlp_f, text="◈ Overlap Detection", bg=PANEL, fg=GREEN,
             font=FONT_HEAD).pack(anchor="w", padx=12, pady=(10, 4))
    e5_ovlp = tk.Text(ovlp_f, bg=BG2, fg=GREEN, font=FONT_MONO, height=5, width=35,
                      highlightbackground=BORDER, highlightthickness=1,
                      relief="flat", insertbackground=GREEN)
    e5_ovlp.insert("end", "10.0.0.0/8\n10.1.0.0/16\n172.16.0.0/12")
    e5_ovlp.pack(padx=12, pady=4)
    ovlp_out = styled_text(ovlp_f, h=6, w=40)
    ovlp_out.pack(padx=12, pady=4)

    def do_overlap():
        raw  = e5_ovlp.get("1.0", "end").replace(",", "\n")
        nets = [n.strip() for n in raw.splitlines() if n.strip()]
        try:
            overlaps = SubnetEngine.check_overlap(nets)
            if overlaps:
                lines = [("⚠  Overlapping Networks Detected:", "warn"), ""]
                for a, b in overlaps:
                    lines.append((f"  {a}  ↔  {b}", "error"))
            else:
                lines = [("✓  No overlaps detected.", "ok")]
            output_write(ovlp_out, lines)
        except Exception as ex:
            output_write(ovlp_out, [(f"Error: {ex}", "error")])

    styled_button(ovlp_f, "  ▶  CHECK  ", do_overlap).pack(pady=(0, 10))

    # IP-in-Subnet Check
    ip_f = styled_frame(util_right, bg=PANEL)
    ip_f.pack(fill="x", pady=4)
    tk.Label(ip_f, text="◈ IP-in-Subnet Check", bg=PANEL, fg=GREEN,
             font=FONT_HEAD).pack(anchor="w", padx=12, pady=(10, 4))
    r1 = tk.Frame(ip_f, bg=PANEL)
    r1.pack(fill="x", padx=12)
    tk.Label(r1, text="IP:", bg=PANEL, fg=TEXT_DIM, font=FONT_MAIN).pack(side="left")
    e5_ip = styled_entry(r1, width=18)
    e5_ip.insert(0, "192.168.1.50")
    e5_ip.pack(side="left", padx=4, pady=4)
    r2 = tk.Frame(ip_f, bg=PANEL)
    r2.pack(fill="x", padx=12)
    tk.Label(r2, text="CIDR:", bg=PANEL, fg=TEXT_DIM, font=FONT_MAIN).pack(side="left")
    e5_cidr = styled_entry(r2, width=18)
    e5_cidr.insert(0, "192.168.1.0/24")
    e5_cidr.pack(side="left", padx=4, pady=4)
    ip_result = tk.Label(ip_f, text="", bg=PANEL, fg=CYAN, font=FONT_HEAD)
    ip_result.pack(pady=4)

    def do_ip_check():
        try:
            result = SubnetEngine.ip_in_subnet(e5_ip.get(), e5_cidr.get())
            if result:
                ip_result.config(text=f"✓  {e5_ip.get()} is IN {e5_cidr.get()}", fg=GREEN)
            else:
                ip_result.config(text=f"✗  {e5_ip.get()} is NOT in {e5_cidr.get()}", fg=RED)
        except Exception as ex:
            ip_result.config(text=str(ex), fg=RED)

    styled_button(ip_f, "  ▶  CHECK  ", do_ip_check).pack(pady=(0, 10))

    # Host Address List
    hl_f = styled_frame(util_right, bg=PANEL)
    hl_f.pack(fill="both", expand=True, pady=4)
    tk.Label(hl_f, text="◈ Host Address List", bg=PANEL, fg=GREEN,
             font=FONT_HEAD).pack(anchor="w", padx=12, pady=(10, 4))
    r3 = tk.Frame(hl_f, bg=PANEL)
    r3.pack(fill="x", padx=12)
    tk.Label(r3, text="CIDR:", bg=PANEL, fg=TEXT_DIM, font=FONT_MAIN).pack(side="left")
    e5_hl = styled_entry(r3, width=18)
    e5_hl.insert(0, "192.168.0.0/28")
    e5_hl.pack(side="left", padx=4, pady=4)
    tk.Label(r3, text="Limit:", bg=PANEL, fg=TEXT_DIM, font=FONT_MAIN).pack(side="left", padx=4)
    e5_limit = styled_entry(r3, width=5)
    e5_limit.insert(0, "50")
    e5_limit.pack(side="left", padx=4)
    hl_out = styled_text(hl_f, h=10, w=40)
    hl_out.pack(fill="both", expand=True, padx=12, pady=4)

    def do_hostlist():
        try:
            limit = int(e5_limit.get()) if e5_limit.get().strip() else 20
            hosts = SubnetEngine.ping_sweep_preview(e5_hl.get(), min(limit, 254))
            lines = [(f"  Hosts in {e5_hl.get()} (first {len(hosts)}):", "head"), sep_line()]
            for i, h in enumerate(hosts, 1):
                lines.append((f"  {i:>4}.  {h}", "val"))
            lines.append(sep_line())
            output_write(hl_out, lines)
        except Exception as ex:
            output_write(hl_out, [(f"Error: {ex}", "error")])

    styled_button(hl_f, "  ▶  LIST  ", do_hostlist).pack(pady=(0, 8))

    # ── Status Bar ──
    bar = tk.Frame(root, bg=BG2, height=26)
    bar.pack(fill="x", side="bottom")
    bar.pack_propagate(False)
    tk.Label(bar, text="◈ NetSlice Pro  |  IPv4 Subnetting Engine  |  Dark Green Edition",
             bg=BG2, fg=DGREEN, font=FONT_TINY).pack(side="left", padx=16, pady=4)
    tk.Label(bar, text="Ready", bg=BG2, fg=GREEN, font=FONT_TINY).pack(side="right", padx=16)

    # Enter key per tab
    tab_actions = [do_info, do_subnet_div, do_by_hosts, do_vlsm]
    def on_enter(event):
        idx = nb.index(nb.select())
        if idx < len(tab_actions):
            tab_actions[idx]()
    root.bind("<Return>", on_enter)

    root.mainloop()


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetSlice Pro — Industry Subnetting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subnet_tool.py                           # Launch GUI
  python subnet_tool.py --cli                     # Interactive terminal menu
  python subnet_tool.py --info 192.168.1.0/24     # Quick network info
  python subnet_tool.py --subnet 10.0.0.0/16 --count 8
  python subnet_tool.py --subnet 10.0.0.0/16 --hosts 50
  python subnet_tool.py --vlsm 10.0.0.0/20 --hosts 100,50,30,10
  python subnet_tool.py --summarize 192.168.0.0/24,192.168.1.0/24
  python subnet_tool.py --overlap 10.0.0.0/8,10.1.0.0/16
  python subnet_tool.py --check-ip 10.1.2.3 --in-net 10.0.0.0/8
  python subnet_tool.py --info 10.0.0.0/8 --json
        """
    )
    parser.add_argument("--cli",       action="store_true")
    parser.add_argument("--info",      metavar="CIDR")
    parser.add_argument("--subnet",    metavar="CIDR")
    parser.add_argument("--count",     metavar="N", type=int)
    parser.add_argument("--hosts",     metavar="N")
    parser.add_argument("--vlsm",      metavar="CIDR")
    parser.add_argument("--summarize", metavar="CIDRS")
    parser.add_argument("--overlap",   metavar="CIDRS")
    parser.add_argument("--check-ip",  metavar="IP",   dest="check_ip")
    parser.add_argument("--in-net",    metavar="CIDR", dest="in_net")
    parser.add_argument("--json",      action="store_true")
    args = parser.parse_args()

    try:
        if args.info:
            info = SubnetEngine.network_info(args.info)
            if args.json: print(json.dumps(info, indent=2))
            else: TerminalUI.banner(); TerminalUI.print_network_info(info)
            return

        if args.subnet and args.count:
            subnets = SubnetEngine.subnet_by_count(args.subnet, args.count)
            if args.json: print(json.dumps(subnets, indent=2))
            else:
                TerminalUI.banner()
                for i, s in enumerate(subnets, 1):
                    TerminalUI.print_network_info(s, f"Subnet {i}/{len(subnets)}")
            return

        if args.subnet and args.hosts and "," not in args.hosts:
            info = SubnetEngine.subnet_by_hosts(args.subnet, int(args.hosts))
            if args.json: print(json.dumps(info, indent=2))
            else: TerminalUI.banner(); TerminalUI.print_network_info(info)
            return

        if args.vlsm and args.hosts:
            reqs = [int(x.strip()) for x in args.hosts.split(",") if x.strip()]
            subnets = SubnetEngine.vlsm(args.vlsm, reqs)
            if args.json: print(json.dumps(subnets, indent=2))
            else:
                TerminalUI.banner()
                for i, s in enumerate(subnets, 1):
                    TerminalUI.print_network_info(s, f"VLSM Subnet {i} (req {s['required_hosts']} hosts)")
            return

        if args.summarize:
            nets = [n.strip() for n in args.summarize.split(",") if n.strip()]
            result = SubnetEngine.summarize(nets)
            if args.json: print(json.dumps({"summary": result}))
            else: print(f"\n  Summary: {TerminalUI.GREEN}{result}{TerminalUI.RESET}\n")
            return

        if args.overlap:
            nets = [n.strip() for n in args.overlap.split(",") if n.strip()]
            overlaps = SubnetEngine.check_overlap(nets)
            if args.json: print(json.dumps(overlaps))
            else:
                for a, b in overlaps:
                    print(f"  {TerminalUI.RED}OVERLAP: {a} ↔ {b}{TerminalUI.RESET}")
                if not overlaps:
                    print(f"  {TerminalUI.GREEN}No overlaps.{TerminalUI.RESET}")
            return

        if args.check_ip and args.in_net:
            result = SubnetEngine.ip_in_subnet(args.check_ip, args.in_net)
            if args.json:
                print(json.dumps({"ip": args.check_ip, "network": args.in_net, "in_subnet": result}))
            else:
                s = f"{TerminalUI.GREEN}✓ IN" if result else f"{TerminalUI.RED}✗ NOT IN"
                print(f"\n  {s}  {args.check_ip} → {args.in_net}{TerminalUI.RESET}\n")
            return

    except Exception as e:
        print(f"\n  {TerminalUI.RED}Error: {e}{TerminalUI.RESET}\n")
        sys.exit(1)

    if args.cli:
        TerminalUI.interactive_menu()
    else:
        launch_gui()


if __name__ == "__main__":
    main()
