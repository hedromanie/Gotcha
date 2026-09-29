"""Access tab: ping, port scan, traceroute, adapters, net scan."""
import os
import sys
import json
import socket
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import srp, sr1
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr

# Минимальный OUI → тип устройства (префикс MAC без :)
_OUI_HINTS = {
    "000C29": "VMware", "005056": "VMware", "000569": "VMware",
    "080027": "VirtualBox", "00155D": "Hyper-V", "001C42": "Parallels",
    "525400": "QEMU/KVM", "0003FF": "Microsoft", "000D3A": "Microsoft",
    "7C1E52": "Microsoft",
    "B8AEED": "Xiaomi", "28E31F": "Xiaomi", "64CC2E": "Xiaomi", "F0B429": "Xiaomi",
    "3C5AB4": "Google", "54EF92": "Google", "001A11": "Google Nest",
    "FCF136": "Samsung", "001632": "Samsung", "5C0A5B": "Samsung",
    "A4C3F0": "Intel", "001B21": "Intel", "F0D5BF": "Intel", "3C970E": "Intel",
    "E4F89C": "Intel", "001E67": "Intel",
    "0026B9": "Dell", "F8B156": "Dell", "18A905": "Dell",
    "001A2F": "Cisco", "001A6D": "Cisco", "00D0D3": "Cisco",
    "18E829": "Ubiquiti", "FC0A81": "Ubiquiti", "B4FBE4": "Ubiquiti",
    "802AA8": "Ubiquiti", "F4F5E8": "Ubiquiti",
    "DC447D": "Apple", "AC87A3": "Apple", "F0B479": "Apple",
    "A4B197": "Apple", "3C0754": "Apple", "88E9FE": "Apple",
    "001D0F": "TP-Link", "50C7BF": "TP-Link", "C0C9E3": "TP-Link",
    "D8EB97": "TP-Link", "14CC20": "TP-Link", "0019E0": "TP-Link",
    "00E04C": "Realtek",
    "F8E43B": "ASUS", "04D4C4": "ASUS", "00E018": "ASUS", "1C872C": "ASUS",
    "B0C090": "Hikvision", "4447CC": "Hikvision",
    "001E58": "D-Link", "1C7EE5": "D-Link", "001B11": "D-Link", "C8D3A3": "D-Link",
    "B827EB": "RaspberryPi", "DCA632": "RaspberryPi", "E45F01": "RaspberryPi",
    "28CDC1": "RaspberryPi",
    "001E10": "Huawei", "00E0FC": "Huawei", "AC853D": "Huawei",
    "F8F082": "ZTE",
    "001CC0": "Espressif", "A020A6": "Espressif", "24A160": "Espressif",
    "30AEA4": "Espressif", "C44F33": "Espressif",
    "00D861": "MSI",
}



class AccessTabMixin:
    def setup_access_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill="both", expand=True, padx=8, pady=8)
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill="x", padx=5, pady=5)
        input_frame = ttk.LabelFrame(top_frame, text="Базовые функции доступа")
        input_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(input_frame, text="IP адрес:").grid(row=0, column=0, padx=4, pady=3, sticky="w")
        self.access_ip = ttk.Entry(input_frame, width=18, font=("Arial", 9))
        self.access_ip.grid(row=0, column=1, padx=4, pady=3, sticky="w")
        self.access_ip.insert(0, "192.168.1.1")
        ttk.Label(input_frame, text="Интерфейс:").grid(row=0, column=2, padx=4, pady=3, sticky="w")
        self.access_interface = ttk.Combobox(
            input_frame, width=15, font=("Arial", 9), values=self.network_interfaces
        )
        self.access_interface.grid(row=0, column=3, padx=4, pady=3, sticky="w")
        self.access_interface.set(self.active_interface)
        button_frame1 = ttk.Frame(input_frame)
        button_frame1.grid(row=1, column=0, columnspan=4, pady=6)
        ttk.Button(button_frame1, text="ICMP Ping", command=self.run_ping, width=12).pack(
            side="left", padx=3
        )
        ttk.Button(button_frame1, text="Port Scan", command=self.run_port_scan, width=12).pack(
            side="left", padx=3
        )
        ttk.Button(button_frame1, text="Traceroute", command=self.run_traceroute, width=12).pack(
            side="left", padx=3
        )
        button_frame2 = ttk.Frame(input_frame)
        button_frame2.grid(row=2, column=0, columnspan=4, pady=6)
        ttk.Button(
            button_frame2, text="Сетевые адаптеры", command=self.show_network_info, width=18
        ).pack(side="left", padx=2)
        ttk.Button(
            button_frame2, text="Сканировать сеть", command=self.net_scan, width=18
        ).pack(side="left", padx=2)
        self.port_scan_stop_event = threading.Event()
        self.port_scan_running = False
        output_frame = ttk.LabelFrame(main_frame, text="Результаты")
        output_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.access_output = scrolledtext.ScrolledText(
            output_frame, height=18, wrap=tk.WORD, font=("Consolas", 8)
        )
        self.access_output.pack(fill="both", expand=True, padx=5, pady=5)
        ttk.Button(
            output_frame, text="Сохранить лог", command=lambda: self.save_log(self.access_output), width=14
        ).pack(pady=4)

    def _access_log(self, text):
        def _do():
            try:
                self.access_output.insert("end", text)
                self.access_output.see("end")
            except Exception:
                pass
        try:
            self.root.after(0, _do)
        except Exception:
            pass

    def _ports_json_path(self):
        """main/other/ports.json (рядом с guide), либо gotcha/../other."""
        candidates = []
        if getattr(sys, "frozen", False):
            base = os.path.dirname(sys.executable)
            candidates.append(os.path.join(base, "other", "ports.json"))
            candidates.append(os.path.join(base, "ports.json"))
        else:
            # access.py → tabs → gotcha → main
            here = os.path.dirname(os.path.abspath(__file__))
            main_dir = os.path.dirname(os.path.dirname(here))
            candidates.append(os.path.join(main_dir, "other", "ports.json"))
            candidates.append(os.path.join(os.getcwd(), "other", "ports.json"))
            candidates.append(os.path.join(os.getcwd(), "main", "other", "ports.json"))
        for p in candidates:
            if os.path.isfile(p):
                return p
        return candidates[0] if candidates else "ports.json"

    def _load_ports_config(self):
        path = self._ports_json_path()
        default_ports = [
            {"port": p, "service": s}
            for p, s in [
                (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
                (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
                (443, "https"), (445, "smb"), (993, "imaps"), (995, "pop3s"),
                (3389, "rdp"),
            ]
        ]
        cfg = {"ports": default_ports, "timeout_sec": 0.4, "max_workers": 64}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get("ports"):
                cfg.update({k: data[k] for k in data if k in ("ports", "timeout_sec", "max_workers")})
            elif isinstance(data, list):
                cfg["ports"] = data
        except FileNotFoundError:
            self._access_log(f"[PortScan] {path} не найден — встроенный список портов\n")
        except Exception as e:
            self._access_log(f"[PortScan] ошибка чтения {path}: {e}\n")
        return cfg, path

    def run_port_scan(self):
        if getattr(self, "port_scan_running", False):
            self.port_scan_stop_event.set()
            self._access_log("Port Scan: остановка...\n")
            return

        def worker():
            self.port_scan_running = True
            self.port_scan_stop_event.clear()
            ip = self.access_ip.get().strip()
            if not ip:
                self._access_log("Введите IP\n")
                self.port_scan_running = False
                return
            cfg, path = self._load_ports_config()
            ports = []
            for item in cfg.get("ports", []):
                if isinstance(item, int):
                    ports.append((item, ""))
                elif isinstance(item, dict) and "port" in item:
                    ports.append((int(item["port"]), str(item.get("service", ""))))
            timeout = float(cfg.get("timeout_sec", 0.4))
            workers = int(cfg.get("max_workers", 64))
            workers = max(1, min(workers, 128))
            self._access_log(
                f"Port Scan {ip}: {len(ports)} портов из {path}, "
                f"timeout={timeout}s, threads={workers}\n"
            )
            open_list = []
            lock = threading.Lock()

            def probe(port_svc):
                if self.port_scan_stop_event.is_set():
                    return None
                port, svc = port_svc
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    res = sock.connect_ex((ip, port))
                    sock.close()
                    if res == 0:
                        return (port, svc or "?")
                except Exception:
                    pass
                return None

            try:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futs = [pool.submit(probe, ps) for ps in ports]
                    for fut in as_completed(futs):
                        if self.port_scan_stop_event.is_set():
                            break
                        r = fut.result()
                        if r:
                            with lock:
                                open_list.append(r)
                            self._access_log(
                                f"  open  {r[0]}/tcp  {r[1]}\n"
                            )
            except Exception as e:
                self._access_log(f"Port Scan error: {e}\n")
            open_list.sort(key=lambda x: x[0])
            self._access_log(
                f"Готово: open={len(open_list)} / scanned={len(ports)}"
                + (" (stopped)\n" if self.port_scan_stop_event.is_set() else "\n")
            )
            self.port_scan_running = False

        threading.Thread(target=worker, daemon=True).start()

    def run_ping(self):
        def ping_worker():
            ip = self.access_ip.get()
            self._access_log(f"Ping {ip}...\n")
            try:
                process = subprocess.Popen(
                    ["ping", "-n", "4", ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    text=True,
                    encoding="cp866" if os.name == "nt" else "utf-8",
                    errors="replace",
                    bufsize=1,
                )
                for line in iter(process.stdout.readline, ""):
                    self._access_log(line)
                process.stdout.close()
                process.wait()
            except Exception as e:
                self._access_log(f"Ошибка: {e}\n")

        threading.Thread(target=ping_worker, daemon=True).start()

    def run_traceroute(self):
        def traceroute_worker():
            ip = self.access_ip.get()
            self._access_log(f"Traceroute к {ip}...\n")
            try:
                if os.name == "nt":
                    cmd = ["tracert", "-d", "-h", "30", "-w", "1000", ip]
                    encoding = "cp866"
                else:
                    cmd = ["traceroute", "-n", "-m", "30", "-w", "1", ip]
                    encoding = "utf-8"
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    text=True,
                    encoding=encoding,
                    errors="replace",
                    bufsize=1,
                )
                for line in iter(process.stdout.readline, ""):
                    self._access_log(line)
                process.stdout.close()
                process.wait()
                self._access_log("\nTraceroute завершен.\n")
            except Exception as e:
                self._access_log(f"Ошибка Traceroute: {e}\n")

        threading.Thread(target=traceroute_worker, daemon=True).start()

    @staticmethod
    def _oui_hint(mac: str) -> str:
        m = (mac or "").replace(":", "").replace("-", "").upper()
        if len(m) < 6:
            return ""
        return _OUI_HINTS.get(m[:6], "")

    @staticmethod
    def _guess_os_ttl(ttl):
        if ttl is None:
            return ""
        try:
            ttl = int(ttl)
        except Exception:
            return ""
        if ttl <= 64:
            return "unix/linux?"
        if ttl <= 128:
            return "windows?"
        if ttl <= 255:
            return "network-os?"
        return ""

    def _probe_host_light(self, ip):
        """Hostname + ICMP TTL + несколько TCP-портов (быстро, без баннеров)."""
        info = {"hostname": "", "ttl": None, "os": "", "ports": []}
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.4)
            try:
                hn = socket.getfqdn(ip)
                if hn and hn != ip:
                    info["hostname"] = hn
            finally:
                socket.setdefaulttimeout(old)
        except Exception:
            pass
        try:
            ans = sr1(IP(dst=ip) / ICMP(), timeout=0.5, verbose=0)
            if ans is not None and IP in ans:
                info["ttl"] = int(ans[IP].ttl)
                info["os"] = self._guess_os_ttl(info["ttl"])
        except Exception:
            pass
        for port, name in (
            (22, "ssh"), (80, "http"), (443, "https"),
            (445, "smb"), (3389, "rdp"), (8080, "http-alt"),
        ):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.25)
                if s.connect_ex((ip, port)) == 0:
                    info["ports"].append(name)
                s.close()
            except Exception:
                pass
        return info

    def net_scan(self):
        def scan_worker():
            ip = self.access_ip.get().strip()
            if not ip:
                self._access_log("Введите IP адрес (например, 192.168.1.1)\n")
                return
            parts = ip.split(".")
            if len(parts) != 4:
                self._access_log("Некорректный IP\n")
                return
            base = ".".join(parts[:3]) + "."
            self._access_log(f"ARP-скан {base}0/24...\n")
            iface = self.access_interface.get() or None
            try:
                ans, unans = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=base + "0/24"),
                    timeout=2,
                    verbose=0,
                    iface=iface,
                )
            except Exception as e:
                self._access_log(f"Ошибка сканирования: {e}\n")
                return
            hosts = []
            if ans:
                for _sent, received in ans:
                    ip_addr = received.psrc
                    mac_addr = received.hwsrc
                    vendor = self._oui_hint(mac_addr)
                    hosts.append((ip_addr, mac_addr, vendor))
                hosts.sort(key=lambda h: tuple(int(x) for x in h[0].split(".")))

            self._access_log(f"Найдено {len(hosts)} хостов — лёгкий профайл (DNS/TTL/порты)...\n")
            self._access_log("\n" + "=" * 88 + "\n")
            for ip_addr, mac_addr, vendor in hosts:
                profile = self._probe_host_light(ip_addr)
                notes = []
                if ip_addr.endswith(".1") or ip_addr.endswith(".254"):
                    notes.append("gw?")
                if vendor in ("VMware", "VirtualBox", "Hyper-V", "Parallels", "QEMU/KVM"):
                    notes.append("vm")
                if vendor == "Espressif":
                    notes.append("iot")
                if vendor == "RaspberryPi":
                    notes.append("rpi")
                if "rdp" in profile["ports"] or "smb" in profile["ports"]:
                    notes.append("win-svc?")
                line1 = f"{ip_addr:16}  {mac_addr:17}  {(vendor or '-'):12}"
                self._access_log(line1 + "\n")
                bits = []
                if profile["hostname"]:
                    bits.append(f"name={profile['hostname']}")
                if profile["ttl"] is not None:
                    bits.append(f"ttl={profile['ttl']}")
                if profile["os"]:
                    bits.append(profile["os"])
                if profile["ports"]:
                    bits.append("open=" + ",".join(profile["ports"]))
                if notes:
                    bits.append("note=" + ",".join(notes))
                if bits:
                    self._access_log("  " + " | ".join(bits) + "\n")
                else:
                    self._access_log("  (нет доп. данных)\n")
            self._access_log("=" * 88 + "\n")
            self._access_log(f"Готово. Хостов: {len(hosts)}\n")

        threading.Thread(target=scan_worker, daemon=True).start()

    def show_network_info(self):
        def worker():
            self._access_log("=== СЕТЕВЫЕ АДАПТЕРЫ ===\n")
            self._access_log(self.get_network_adapters() + "\n")

        threading.Thread(target=worker, daemon=True).start()

    def get_network_adapters(self):
        try:
            result = []
            # Scapy list
            try:
                iface_list = get_if_list()
            except Exception:
                iface_list = []
            # Windows friendly names via psutil if available
            psutil_map = {}
            try:
                import psutil
                for name, addrs in psutil.net_if_addrs().items():
                    stats = psutil.net_if_stats().get(name)
                    up = getattr(stats, "isup", None) if stats else None
                    ips = []
                    mac = ""
                    for a in addrs:
                        if getattr(a, "family", None) == socket.AF_INET:
                            ips.append(a.address)
                        if getattr(a, "family", None) == psutil.AF_LINK if hasattr(psutil, "AF_LINK") else -1:
                            mac = a.address
                    psutil_map[name] = {"ips": ips, "mac": mac, "up": up}
            except Exception:
                pass

            if psutil_map:
                for name, info in psutil_map.items():
                    st = "UP" if info["up"] else ("DOWN" if info["up"] is False else "?")
                    result.append(f"[{st}] {name}")
                    if info["ips"]:
                        result.append(f"  IP: {', '.join(info['ips'])}")
                    if info["mac"]:
                        result.append(f"  MAC: {info['mac']}")
                    result.append("")
            for iface in iface_list:
                try:
                    ip = get_if_addr(iface)
                    mac = get_if_hwaddr(iface)
                    result.append(f"Scapy: {iface}")
                    result.append(f"  IP: {ip}, MAC: {mac}")
                    result.append("")
                except Exception:
                    result.append(f"Scapy: {iface} (no addr)")
                    result.append("")
            return "\n".join(result) if result else "Адаптеры не найдены"
        except Exception as e:
            return f"Ошибка получения сетевых адаптеров: {e}"
