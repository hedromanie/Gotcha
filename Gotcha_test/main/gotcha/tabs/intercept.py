"""Packet intercept / edit / replay tab."""
import time
import random
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sendp, sniff

from gotcha.editor import Editor

class InterceptTabMixin:
    INTERCEPT_MAX_PACKETS = 500

    # -------------------- Intercept tab (без изменений) --------------------
    def setup_intercept_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='y', padx=5, pady=5)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры перехвата")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=4, pady=3)
        ttk.Label(row1, text="Интерфейс:").pack(side='left', padx=2)
        self.intercept_interface = ttk.Combobox(row1, width=15, font=('Arial', 9), values=self.network_interfaces)
        self.intercept_interface.pack(side='left', padx=2)
        self.intercept_interface.set(self.active_interface)
        ttk.Label(row1, text="Фильтр:").pack(side='left', padx=8)
        self.intercept_filter = ttk.Combobox(row1, width=18, font=('Arial', 9), values=[
            "icmp or tcp", "tcp", "udp", "icmp", "arp", "not arp", "not stp", 
            "port 80", "port 443", "host 192.168.1.1", "tcp port 80", "udp port 53"
        ])
        self.intercept_filter.pack(side='left', padx=2)
        self.intercept_filter.set("")
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=4, pady=3)
        ttk.Label(row2, text="Кол-во ответов:").pack(side='left', padx=2)
        self.intercept_response_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.intercept_response_count.pack(side='left', padx=2)
        self.intercept_response_count.insert(0, "0")
        ttk.Label(row2, text="Кол-во для отпр.:").pack(side='left', padx=10)
        self.send_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.send_count.pack(side='left', padx=2)
        self.send_count.insert(0, "10")
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=4, pady=6)
        self.intercept_start_btn = ttk.Button(button_frame, text="Начать перехват", 
                                        command=self.start_packet_intercept, width=14)
        self.intercept_start_btn.pack(side='left', padx=2)
        self.intercept_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                       command=self.stop_packet_intercept, width=12, state='disabled')
        self.intercept_stop_btn.pack(side='left', padx=2)
        ttk.Button(button_frame, text="Захватить выбранный", 
              command=self.capture_selected_intercept_packet, width=18).pack(side='left', padx=2)
        ttk.Button(button_frame, text="Редактировать", 
              command=self.edit_selected_intercept_packet, width=13).pack(side='left', padx=1)
        packets_frame = ttk.LabelFrame(left_frame, text="Перехваченные пакеты")
        packets_frame.pack(fill='both', expand=True, padx=5, pady=5)
        columns = ("№", "Время", "Источник", "Назначение", "Протокол", "Длина", "Информация")
        self.intercept_tree = ttk.Treeview(packets_frame, columns=columns, show='headings', height=12)
        for col in columns:
            self.intercept_tree.heading(col, text=col)
            self.intercept_tree.column(col, width=90)
        self.intercept_tree.column("№", width=40)
        self.intercept_tree.column("Время", width=80)
        self.intercept_tree.column("Источник", width=120)
        self.intercept_tree.column("Назначение", width=120)
        self.intercept_tree.column("Протокол", width=70)
        self.intercept_tree.column("Длина", width=50)
        self.intercept_tree.column("Информация", width=150)
        tree_scroll = ttk.Scrollbar(packets_frame, orient="vertical", command=self.intercept_tree.yview)
        self.intercept_tree.configure(yscrollcommand=tree_scroll.set)
        self.intercept_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')
        control_frame = ttk.LabelFrame(right_frame, text="Управление пакетами")
        control_frame.pack(fill='x', padx=5, pady=5)
        info_frame = ttk.LabelFrame(control_frame, text="Текущие пакеты")
        info_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(info_frame, text="Захваченный:").pack(anchor='w', pady=1)
        self.captured_packet_info = ttk.Label(info_frame, text="Нет", wraplength=300)
        self.captured_packet_info.pack(anchor='w', pady=1, fill='x')
        ttk.Label(info_frame, text="Отредактированный:").pack(anchor='w', pady=1)
        self.edited_packet_info = ttk.Label(info_frame, text="Нет", wraplength=300)
        self.edited_packet_info.pack(anchor='w', pady=1, fill='x')
        send_frame = ttk.Frame(control_frame)
        send_frame.pack(fill='x', padx=5, pady=8)
        ttk.Button(send_frame, text="Отправить захваченный", 
              command=self.send_captured_packet, width=20).pack(pady=2)
        ttk.Button(send_frame, text="Отправить отредактированный", 
              command=self.send_edited_packet, width=20).pack(pady=2)
        ttk.Button(control_frame, text="Очистить список", 
              command=self.clear_intercept_list, width=20).pack(pady=5)
        log_frame = ttk.LabelFrame(right_frame, text="Лог перехвата")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.intercept_log = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=('Consolas', 8))
        self.intercept_log.pack(fill='both', expand=True, padx=5, pady=5)
        ttk.Button(log_frame, text="Сохранить лог", 
              command=lambda: self.save_log(self.intercept_log), width=14).pack(pady=4)
        self.intercept_tree.bind('<<TreeviewSelect>>', self.on_intercept_packet_select)

    def on_intercept_packet_select(self, event):
        selection = self.intercept_tree.selection()
        if not selection:
            return
        item = selection[0]
        packet_info = self.intercept_tree.item(item, 'values')
        index = int(packet_info[0]) - 1
        if 0 <= index < len(self.intercept_packets):
            self.selected_packet = self.intercept_packets[index]
            self.intercept_log.insert('end', f"\n--- ВЫБРАН #{packet_info[0]} ---\n")
            self.intercept_log.insert('end', f"Время: {packet_info[1]}\n")
            self.intercept_log.insert('end', f"Источник: {packet_info[2]}\n")
            self.intercept_log.insert('end', f"Назначение: {packet_info[3]}\n")
            self.intercept_log.insert('end', f"Протокол: {packet_info[4]}\n")
            self.intercept_log.insert('end', f"Длина: {packet_info[5]} байт\n")
            self.intercept_log.insert('end', f"Информация: {packet_info[6]}\n")
            self.intercept_log.see('end')

    def capture_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет")
            return
        self.captured_packet = self.selected_packet
        self.captured_packet_info.config(text=f"Захвачен: {self.selected_packet.summary()}")
        self.intercept_log.insert('end', f"\nПакет захвачен: {self.selected_packet.summary()}\n")

    def edit_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет")
            return
        def callback(edited_packet, save_packet):
            if save_packet:
                self.edited_packet = edited_packet
                self.edited_packet_info.config(text=f"Отредактирован: {edited_packet.summary()}")
                self.intercept_log.insert('end', f"\nПакет сохранён: {edited_packet.summary()}\n")
        Editor(self.root, self.selected_packet, callback)

    def send_captured_packet(self):
        if self.captured_packet is None:
            self.intercept_log.insert('end', "Нет захваченного пакета для отправки!\n")
            return
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            for i in range(count):
                sendp(self.captured_packet, iface=interface, verbose=0)
            self.intercept_log.insert('end', f"Отправлено {count} копий захваченного пакета\n")
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки: {str(e)}\n")

    def send_edited_packet(self):
        if self.edited_packet is None:
            self.intercept_log.insert('end', "Нет отредактированного пакета для отправки!\n")
            return
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            for i in range(count):
                sendp(self.edited_packet, iface=interface, verbose=0)
            self.intercept_log.insert('end', f"Отправлено {count} копий отредактированного пакета\n")
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки: {str(e)}\n")

    def clear_intercept_list(self):
        for item in self.intercept_tree.get_children():
            self.intercept_tree.delete(item)
        self.intercept_packets.clear()
        self.intercept_log.insert('end', "Список пакетов очищен\n")

    def add_packet_to_intercept_tree(self, data):
        """data: (num, time, src, dst, proto, length, info, packet)"""
        def _do():
            try:
                if isinstance(data, dict):
                    num = data.get("number")
                    ts, src, dst, proto = data.get("time"), data.get("src"), data.get("dst"), data.get("proto")
                    length, info, pkt = data.get("len"), data.get("info", ""), data.get("packet")
                else:
                    num, ts, src, dst, proto, length, info, pkt = data
                while len(self.intercept_packets) >= self.INTERCEPT_MAX_PACKETS:
                    self.intercept_packets.pop(0)
                    children = self.intercept_tree.get_children()
                    if children:
                        self.intercept_tree.delete(children[0])
                self.intercept_packets.append(pkt)
                self.intercept_tree.insert(
                    "", "end", values=(num, ts, src, dst, proto, length, info)
                )
            except Exception as e:
                print(f"[Gotcha] intercept tree: {e}")
        try:
            self.root.after(0, _do)
        except Exception:
            pass


    def start_packet_intercept(self):
        self.packet_intercept_running = True
        self.intercept_start_btn.config(state='disabled')
        self.intercept_stop_btn.config(state='normal')
        self.intercept_thread = threading.Thread(
            target=self.intercept_worker,
            args=(self.intercept_filter.get(), self.intercept_interface.get())
        )
        self.intercept_thread.daemon = True
        self.intercept_thread.start()
        self.intercept_log.insert('end', "Перехват пакетов запущен\n")
        self.status_var.set("Перехват запущен")

    def stop_packet_intercept(self):
        self.packet_intercept_running = False
        self.intercept_start_btn.config(state='normal')
        self.intercept_stop_btn.config(state='disabled')
        self.intercept_log.insert('end', "Перехват остановлен\n")
        self.status_var.set("Перехват остановлен")

    def get_packet_info(self, packet):
        src = "Unknown"
        dst = "Unknown"
        protocol = "Unknown"
        length = len(packet)
        info = ""
        if packet.haslayer(Ether):
            src = packet[Ether].src
            dst = packet[Ether].dst
        if packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            protocol = "IPv6"
            if packet.haslayer(TCP):
                protocol = "TCP"
                info = f"Ports: {packet[TCP].sport}->{packet[TCP].dport} Flags: {packet[TCP].flags}"
            elif packet.haslayer(UDP):
                protocol = "UDP" 
                info = f"Ports: {packet[UDP].sport}->{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
        elif packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = "IP"
            if packet.haslayer(TCP):
                protocol = "TCP"
                info = f"Ports: {packet[TCP].sport}->{packet[TCP].dport} Flags: {packet[TCP].flags}"
            elif packet.haslayer(UDP):
                protocol = "UDP" 
                info = f"Ports: {packet[UDP].sport}->{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
        elif packet.haslayer(ARP):
            protocol = "ARP"
            info = f"Operation: {packet[ARP].op}"
        return (src, dst, protocol, length, info)

    def intercept_worker(self, filter_str, interface):
        def intercept_handler(packet):
            if not self.packet_intercept_running:
                return
            timestamp = time.strftime("%H:%M:%S")
            src, dst, proto, length, info = self.get_packet_info(packet)
            num = len(self.intercept_packets) + 1
            data = (num, timestamp, src, dst, proto, length, info, packet)
            self.root.after(0, self.add_packet_to_intercept_tree, data)
            try:
                resp_count = int(self.intercept_response_count.get())
            except Exception as e:
                print(f"[Gotcha] error: {e}")
                resp_count = 0
            for i in range(resp_count):
                resp = self.create_response_packet(packet)
                if resp:
                    try:
                        sendp(resp, iface=interface, verbose=0)
                        self.intercept_log.insert('end', f"  -> Ответ {i+1} отправлен\n")
                    except Exception as e:
                        self.intercept_log.insert('end', f"  -> Ошибка ответа: {str(e)}\n")
        try:
            sniff(filter=filter_str, iface=interface, prn=intercept_handler,
                  stop_filter=lambda x: not self.packet_intercept_running)
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка сниффинга: {str(e)}\n")

    def create_response_packet(self, original_packet):
        try:
            if original_packet.haslayer(ICMP) and original_packet[ICMP].type == 8:
                if original_packet.haslayer(IPv6):
                    return IPv6(src=original_packet[IPv6].dst, dst=original_packet[IPv6].src)/ICMP(type=0, id=original_packet[ICMP].id, seq=original_packet[ICMP].seq)
                else:
                    return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/ICMP(type=0, id=original_packet[ICMP].id, seq=original_packet[ICMP].seq)
            elif original_packet.haslayer(TCP):
                if original_packet.haslayer(IPv6):
                    ip_layer = IPv6(src=original_packet[IPv6].dst, dst=original_packet[IPv6].src)
                else:
                    ip_layer = IP(src=original_packet[IP].dst, dst=original_packet[IP].src)
                return ip_layer/TCP(
                    sport=original_packet[TCP].dport, 
                    dport=original_packet[TCP].sport,
                    flags="RA",
                    seq=random.randint(1000, 9000),
                    ack=original_packet[TCP].seq + 1
                )
            elif original_packet.haslayer(UDP):
                if original_packet.haslayer(IPv6):
                    ip_layer = IPv6(src=original_packet[IPv6].dst, dst=original_packet[IPv6].src)
                else:
                    ip_layer = IP(src=original_packet[IP].dst, dst=original_packet[IP].src)
                return ip_layer/UDP(
                    sport=original_packet[UDP].dport,
                    dport=original_packet[UDP].sport
                )/b"Response"
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка создания ответа: {str(e)}\n")
        return None

