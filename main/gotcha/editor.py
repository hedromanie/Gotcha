"""Packet editor window."""
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

class Editor:
    def __init__(self, parent, packet, callback):
        self.parent = parent
        self.packet = packet
        self.callback = callback
        self.edited_packet = None
        self.editor_window = tk.Toplevel(parent)
        self.editor_window.title("Редактор пакета")
        self.editor_window.geometry("1000x800")
        self.editor_window.transient(parent)
        self.editor_window.grab_set()
        try:
            _base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.editor_window.iconbitmap(os.path.join(_base, "other", "images", "images.ico"))
        except Exception as e:
            print(f"[Gotcha] suppressed: {e}")
        self.create_widgets()
        self.parse_packet()
    def create_widgets(self):
        main_frame = ttk.Frame(self.editor_window)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        info_frame = ttk.LabelFrame(main_frame, text="Информация о пакете")
        info_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(info_frame, text="Исходный пакет:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.original_info = ttk.Label(info_frame, text=self.packet.summary())
        self.original_info.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        details_frame = ttk.LabelFrame(main_frame, text="Детали пакета")
        details_frame.pack(fill='x', padx=5, pady=5)
        self.packet_details = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.packet_details.pack(fill='both', expand=True, padx=5, pady=5)
        self.packet_details.config(state='normal')
        eth_frame = ttk.LabelFrame(main_frame, text="Ethernet Layer")
        eth_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(eth_frame, text="Source MAC:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.eth_src = ttk.Entry(eth_frame, width=20)
        self.eth_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(eth_frame, text="Dest MAC:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.eth_dst = ttk.Entry(eth_frame, width=20)
        self.eth_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')
        ip_frame = ttk.LabelFrame(main_frame, text="IP Layer")
        ip_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(ip_frame, text="Source IP:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.ip_src = ttk.Entry(ip_frame, width=20)
        self.ip_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(ip_frame, text="Dest IP:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.ip_dst = ttk.Entry(ip_frame, width=20)
        self.ip_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')
        ttk.Label(ip_frame, text="TTL:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.ip_ttl = ttk.Entry(ip_frame, width=10)
        self.ip_ttl.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        transport_frame = ttk.LabelFrame(main_frame, text="Transport Layer")
        transport_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(transport_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.transport_proto = ttk.Combobox(transport_frame, values=["TCP", "UDP", "ICMP", "RAW"], width=10)
        self.transport_proto.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(transport_frame, text="Source Port:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.src_port = ttk.Entry(transport_frame, width=10)
        self.src_port.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(transport_frame, text="Dest Port:").grid(row=1, column=2, padx=5, pady=2, sticky='w')
        self.dst_port = ttk.Entry(transport_frame, width=10)
        self.dst_port.grid(row=1, column=3, padx=5, pady=2, sticky='w')
        tcp_flags_frame = ttk.Frame(transport_frame)
        tcp_flags_frame.grid(row=2, column=0, columnspan=4, pady=5)
        self.tcp_flags_vars = {}
        tcp_flags = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        for i, flag in enumerate(tcp_flags):
            self.tcp_flags_vars[flag] = tk.BooleanVar()
            ttk.Checkbutton(tcp_flags_frame, text=flag, variable=self.tcp_flags_vars[flag]).grid(
                row=0, column=i, padx=2, sticky='w')
        data_frame = ttk.LabelFrame(main_frame, text="Payload Data")
        data_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.payload_data = scrolledtext.ScrolledText(data_frame, height=10, wrap=tk.WORD)
        self.payload_data.pack(fill='both', expand=True, padx=5, pady=5)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        ttk.Button(button_frame, text="Применить изменения", 
                  command=self.apply_changes).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Отмена", 
                  command=self.editor_window.destroy).pack(side='right', padx=5)
    def parse_packet(self):
        if self.packet.haslayer(Ether):
            self.eth_src.insert(0, self.packet[Ether].src)
            self.eth_dst.insert(0, self.packet[Ether].dst)
        ip_layer = None
        if self.packet.haslayer(IPv6):
            ip_layer = self.packet[IPv6]
        elif self.packet.haslayer(IP):
            ip_layer = self.packet[IP]
        if ip_layer:
            self.ip_src.insert(0, ip_layer.src)
            self.ip_dst.insert(0, ip_layer.dst)
            if hasattr(ip_layer, 'ttl'):
                self.ip_ttl.insert(0, str(ip_layer.ttl))
            elif hasattr(ip_layer, 'hlim'):
                self.ip_ttl.insert(0, str(ip_layer.hlim))
            if self.packet.haslayer(TCP):
                self.transport_proto.set("TCP")
                self.src_port.insert(0, str(self.packet[TCP].sport))
                self.dst_port.insert(0, str(self.packet[TCP].dport))
                flags = self.packet[TCP].flags
                self.tcp_flags_vars["FIN"].set(bool(flags & 0x01))
                self.tcp_flags_vars["SYN"].set(bool(flags & 0x02))
                self.tcp_flags_vars["RST"].set(bool(flags & 0x04))
                self.tcp_flags_vars["PSH"].set(bool(flags & 0x08))
                self.tcp_flags_vars["ACK"].set(bool(flags & 0x10))
                self.tcp_flags_vars["URG"].set(bool(flags & 0x20))
                self.tcp_flags_vars["ECE"].set(bool(flags & 0x40))
                self.tcp_flags_vars["CWR"].set(bool(flags & 0x80))
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except Exception as e:
                        print(f"[Gotcha] error: {e}")
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
            elif self.packet.haslayer(UDP):
                self.transport_proto.set("UDP")
                self.src_port.insert(0, str(self.packet[UDP].sport))
                self.dst_port.insert(0, str(self.packet[UDP].dport))
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except Exception as e:
                        print(f"[Gotcha] error: {e}")
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
            elif self.packet.haslayer(ICMP):
                self.transport_proto.set("ICMP")
            else:
                self.transport_proto.set("RAW")
        self.show_packet_details()
    def show_packet_details(self):
        details = "=== ДЕТАЛИ ПАКЕТА ===\n\n"
        if self.packet.haslayer(Ether):
            details += f"Ethernet:\n"
            details += f"  Source: {self.packet[Ether].src}\n"
            details += f"  Destination: {self.packet[Ether].dst}\n"
            details += f"  Type: {self.packet[Ether].type}\n\n"
        if self.packet.haslayer(IPv6):
            details += f"IPv6:\n"
            details += f"  Source: {self.packet[IPv6].src}\n"
            details += f"  Destination: {self.packet[IPv6].dst}\n"
            details += f"  Hop Limit: {self.packet[IPv6].hlim}\n"
            details += f"  Next Header: {self.packet[IPv6].nh}\n\n"
        elif self.packet.haslayer(IP):
            details += f"IP:\n"
            details += f"  Version: {self.packet[IP].version}\n"
            details += f"  Source: {self.packet[IP].src}\n"
            details += f"  Destination: {self.packet[IP].dst}\n"
            details += f"  TTL: {self.packet[IP].ttl}\n"
            details += f"  Protocol: {self.packet[IP].proto}\n\n"
        if self.packet.haslayer(TCP):
            details += f"TCP:\n"
            details += f"  Source Port: {self.packet[TCP].sport}\n"
            details += f"  Destination Port: {self.packet[TCP].dport}\n"
            details += f"  Flags: {self.packet[TCP].flags}\n"
            details += f"  Sequence: {self.packet[TCP].seq}\n"
            details += f"  Acknowledgment: {self.packet[TCP].ack}\n"
            details += f"  Window: {self.packet[TCP].window}\n\n"
        elif self.packet.haslayer(UDP):
            details += f"UDP:\n"
            details += f"  Source Port: {self.packet[UDP].sport}\n"
            details += f"  Destination Port: {self.packet[UDP].dport}\n"
            details += f"  Length: {self.packet[UDP].len}\n\n"
        elif self.packet.haslayer(ICMP):
            details += f"ICMP:\n"
            details += f"  Type: {self.packet[ICMP].type}\n"
            details += f"  Code: {self.packet[ICMP].code}\n\n"
        if self.packet.haslayer(Raw):
            details += f"Payload:\n"
            payload = self.packet[Raw].load
            details += f"  Length: {len(payload)} bytes\n"
            try:
                details += f"  Hex: {payload.hex()}\n"
                if len(payload) < 100:
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                        if all(c.isprintable() or c in '\n\r\t' for c in text):
                            details += f"  Text: {text}\n"
                    except Exception as e:
                        print(f"[Gotcha] suppressed: {e}")
            except Exception as e:
                print(f"[Gotcha] error: {e}")
                details += f"  Content: {str(payload)}\n"
        self.packet_details.insert('1.0', details)
        self.packet_details.config(state='disabled')
    def apply_changes(self):
        try:
            new_packet = self.create_modified_packet()
            self.edited_packet = new_packet
            self.callback(new_packet, True)
            self.editor_window.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать пакет: {str(e)}")
    def create_modified_packet(self):
        new_packet = Ether()
        if self.eth_src.get():
            dst_mac = self.eth_dst.get() if self.eth_dst.get() else "ff:ff:ff:ff:ff:ff"
            new_packet = Ether(src=self.eth_src.get(), dst=dst_mac)
        if self.ip_src.get() and self.ip_dst.get():
            src = self.ip_src.get()
            dst = self.ip_dst.get()
            try:
                socket.inet_pton(socket.AF_INET6, src)
                socket.inet_pton(socket.AF_INET6, dst)
                ip_packet = IPv6(src=src, dst=dst)
                if self.ip_ttl.get():
                    try:
                        ip_packet.hlim = int(self.ip_ttl.get())
                    except Exception as e:
                        print(f"[Gotcha] suppressed: {e}")
            except socket.error:
                ip_packet = IP(src=src, dst=dst)
                if self.ip_ttl.get():
                    try:
                        ip_packet.ttl = int(self.ip_ttl.get())
                    except Exception as e:
                        print(f"[Gotcha] suppressed: {e}")
            new_packet = new_packet / ip_packet
            proto = self.transport_proto.get()
            if proto == "TCP" and self.src_port.get() and self.dst_port.get():
                tcp_packet = TCP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))
                flags = 0
                if self.tcp_flags_vars["FIN"].get(): flags |= 0x01
                if self.tcp_flags_vars["SYN"].get(): flags |= 0x02
                if self.tcp_flags_vars["RST"].get(): flags |= 0x04
                if self.tcp_flags_vars["PSH"].get(): flags |= 0x08
                if self.tcp_flags_vars["ACK"].get(): flags |= 0x10
                if self.tcp_flags_vars["URG"].get(): flags |= 0x20
                if self.tcp_flags_vars["ECE"].get(): flags |= 0x40
                if self.tcp_flags_vars["CWR"].get(): flags |= 0x80
                tcp_packet.flags = flags
                new_packet = new_packet / tcp_packet
            elif proto == "UDP" and self.src_port.get() and self.dst_port.get():
                new_packet = new_packet / UDP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))
            elif proto == "ICMP":
                new_packet = new_packet / ICMP()
            payload_text = self.payload_data.get('1.0', 'end').strip()
            if payload_text:
                try:
                    payload_bytes = bytes.fromhex(payload_text.replace(' ', '').replace('\n', ''))
                    new_packet = new_packet / Raw(load=payload_bytes)
                except Exception as e:
                    print(f"[Gotcha] error: {e}")
                    new_packet = new_packet / Raw(load=payload_text.encode())
        return new_packet
