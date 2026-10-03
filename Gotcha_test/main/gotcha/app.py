"""Gotcha main application shell."""
import os
import sys
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox
import psutil
from scapy.all import get_if_list, get_if_addr

from gotcha.theme import Theme
from gotcha.utils import find_exe
from gotcha.external_runner import ExternalRunnerMixin
from gotcha.tabs.access import AccessTabMixin
from gotcha.tabs.dhcp import DhcpTabMixin
from gotcha.tabs.arp_spoof import ArpSpoofTabMixin
from gotcha.tabs.dns_spoof import DnsSpoofTabMixin
from gotcha.tabs.mac_flood import MacFloodTabMixin
from gotcha.tabs.dos import DosTabMixin, Sattack
from gotcha.tabs.intercept import InterceptTabMixin
from gotcha.tabs.settings import SettingsTabMixin

class Gotcha(
    AccessTabMixin,
    DhcpTabMixin,
    ArpSpoofTabMixin,
    DnsSpoofTabMixin,
    MacFloodTabMixin,
    DosTabMixin,
    ExternalRunnerMixin,
    InterceptTabMixin,
    SettingsTabMixin,
):
    def __init__(self, root):
        self.root = root
        self.root.title("Gotcha")
        self.root.geometry("1000x700")
        try:
            root.iconbitmap(self._get_doc_path(os.path.join("images", "images.ico")))
        except Exception as e:
            print(f"[Gotcha] suppressed: {e}")
        self.theme_manager = Theme(self.root)
        self.custom_stop_event = None
        self.custom_external_thread = None
        self.current_external_process = None
        self.sniffing_running = False
        self.dhcp_attack_running = False
        self.arp_spoof_running = False
        self.arp_spoof_thread = None
        self._ip_forward_saved = False
        self._ip_forward_original = 0
        self._ip_forward_enabled_by_us = False
        self.dhcp_thread = None
        self.custom_attack_running = False
        self.packet_intercept_running = False
        self.mac_attack_running = False
        self.current_attack_type = None
        self.external_infinite = False
        self.last_offer_time = {}
        self.last_ack_time = {}
        self.external_processes = {}
        self.captured_packet = None
        self.intercept_thread = None
        self.selected_packet = None
        self.intercept_packets = []
        self.edited_packet = None
        # Удалён self.raw_attack (больше не нужен, используем только внешние exe)
        self.scapy_attack = Sattack()
        self.network_interfaces = self.get_interface_list()
        self.active_interface = self.get_active_interface()
        self.setup_gui()
        self.theme_manager.apply_theme("dark")
        self.system_monitor_running = True
        self.setup_system_monitor()
        # DNS Spoofing attributes
        self.dns_spoof_running = False
        self.dns_spoof_thread = None
        self.dns_spoof_stats = {
            'start_time': 0,
            'intercepted': 0,
            'spoofed': 0,
            'last_update': 0,
            'last_intercepted': 0,
            'last_spoofed': 0
        }
        self.dns_spoof_rules = {}
        self.dns_spoof_lock = threading.Lock()
        self.dns_spoof_ttl = 5

    def _get_doc_path(self, filename):
        """Полный путь к файлу в main/other/ (app.py лежит в main/gotcha/)."""
        if getattr(sys, "frozen", False):
            base = os.path.dirname(sys.executable)
        else:
            # main/gotcha/app.py -> main/
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, "other", filename)

    def show_initial_warning(self):
        """Показывает предупреждение при запуске"""
        warning = tk.Toplevel(self.root)
        warning.title("Предупреждение")
        warning.geometry("620x500")
        warning.transient(self.root)
        warning.grab_set()
        try:
            warning.iconbitmap(self._get_doc_path(os.path.join("images", "images.ico")))
        except Exception as e:
            print(f"[Gotcha] suppressed: {e}")
        warning.resizable(False, False)
        # центрирование
        warning.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (warning.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (warning.winfo_height() // 2)
        warning.geometry(f"+{x}+{y}")
        text = """ВНИМАНИЕ!

Перед использованием программы обязательно ознакомьтесь с документацией:

- guide.html  (полное руководство)
- sceheme.html  (сценарии и примеры)

Данная программа предназначена ИСКЛЮЧИТЕЛЬНО для тестирования
собственных сетей или сетей, на которые у вас есть письменное разрешение.

Любое несанкционированное использование против сторонних сетей
является ПРОТИВОЗАКОННЫМ и влечёт уголовную ответственность
(ст. 272–274 УК РФ, Computer Fraud and Abuse Act и др.)

Автор не несёт ответственности за любые последствия неправомерного использования.

Нажимая "Принимаю", вы подтверждаете, что ознакомились с документацией
и обязуетесь использовать программу только в законных целях.
"""
        label = ttk.Label(warning, text=text, justify=tk.LEFT, wraplength=580)
        label.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        frame_btns = ttk.Frame(warning)
        frame_btns.pack(pady=10)

        def open_guide():
            path = self._get_doc_path("guide.html")
            if path and os.path.exists(path):
                webbrowser.open(path)
            else:
                messagebox.showerror("Ошибка", f"Файл guide.html не найден по пути {path}")

        def open_scene():
            path = self._get_doc_path("scheme.html")
            if path and os.path.exists(path):
                webbrowser.open(path)
            else:
                messagebox.showerror("Ошибка", f"Файл scheme.html не найден по пути {path}")

        ttk.Button(frame_btns, text="Открыть guide.html", command=open_guide).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_btns, text="Открыть scheme.html", command=open_scene).pack(side=tk.LEFT, padx=5)

        def accept():
            warning.destroy()

        ttk.Button(warning, text="Принимаю", command=accept).pack(pady=10)

        self.root.wait_window(warning)

    def get_active_interface(self):
        for iface in self.network_interfaces:
            try:
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0':
                    return iface
            except Exception as e:
                print(f"[Gotcha] error: {e}")
                continue
        return self.network_interfaces[0] if self.network_interfaces else "Ethernet"

    def setup_system_monitor(self):
        self.update_system_monitor()

    def update_system_monitor(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            ram_percent = memory.percent
            self.cpu_label.config(text=f"CPU: {cpu_percent:.1f}%")
            self.ram_label.config(text=f"RAM: {ram_percent:.1f}%")
        except Exception as e:
            print(f"[Gotcha] error: {e}")
            self.cpu_label.config(text="CPU: N/A")
            self.ram_label.config(text="RAM: N/A")
        if self.system_monitor_running:
            self.root.after(1000, self.update_system_monitor)

    def get_interface_list(self):
        interfaces = []
        try:
            iface_list = get_if_list()
            for iface in iface_list:
                interfaces.append(iface)
        except Exception as e:
            print(f"[Gotcha] suppressed: {e}")
        if not interfaces:
            interfaces = ["Ethernet", "Wi-Fi", "eth0", "wlan0"]
        return interfaces

    def setup_gui(self):
        main_notebook = ttk.Notebook(self.root)
        main_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        auxiliary_frame = ttk.Frame(main_notebook)
        main_notebook.add(auxiliary_frame, text="Вспомогательное")
        auxiliary_notebook = ttk.Notebook(auxiliary_frame)
        auxiliary_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        access_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(access_frame, text="Доступ")
        self.setup_access_tab(access_frame)
        settings_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(settings_frame, text="Настройки")
        self.setup_settings_tab(settings_frame)
        attacks_frame = ttk.Frame(main_notebook)
        main_notebook.add(attacks_frame, text="Атаки")
        attacks_notebook = ttk.Notebook(attacks_frame)
        attacks_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        intercept_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(intercept_frame, text="Перехват пакетов")
        self.setup_intercept_tab(intercept_frame)
        dhcp_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(dhcp_frame, text="DHCP Starvation")
        self.setup_dhcp_tab(dhcp_frame)
        custom_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(custom_frame, text="DoS атака")
        self.setup_custom_attack_tab(custom_frame)
        arp_spoof_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(arp_spoof_frame, text="ARP Spoofing")
        self.setup_arp_spoof_tab(arp_spoof_frame)
        dns_spoof_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(dns_spoof_frame, text="DNS Spoofing")
        self.setup_dns_spoof_tab(dns_spoof_frame)
        mac_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(mac_frame, text="MAC flood")
        self.setup_mac_flood_tab(mac_frame)
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = ttk.Frame(self.root)
        status_bar.pack(side='bottom', fill='x')
        ttk.Label(status_bar, textvariable=self.status_var, relief='sunken', 
                 font=('Arial', 8), width=50).pack(side='left', fill='x', expand=True)
        self.cpu_label = ttk.Label(status_bar, text="CPU: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.cpu_label.pack(side='right', padx=(2, 0))
        self.ram_label = ttk.Label(status_bar, text="RAM: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.ram_label.pack(side='right', padx=(2, 10))

