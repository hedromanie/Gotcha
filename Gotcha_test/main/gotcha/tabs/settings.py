"""Settings, help, random MAC, on_closing."""
import os
import sys
import random
import webbrowser
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

class SettingsTabMixin:
    # -------------------- Settings tab (с добавлением кнопок для документации) --------------------
    def setup_settings_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        theme_frame = ttk.LabelFrame(main_frame, text="Настройки темы")
        theme_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(theme_frame, text="Светлая тема", 
                  command=lambda: self.theme_manager.apply_theme("light"), width=12).pack(side='left', padx=4, pady=4)
        ttk.Button(theme_frame, text="Тёмная тема", 
                  command=lambda: self.theme_manager.apply_theme("dark"), width=12).pack(side='left', padx=4, pady=4)
        help_frame = ttk.LabelFrame(main_frame, text="Справка и документация")
        help_frame.pack(fill='both', expand=True, padx=5, pady=5)

        # Кнопки для открытия документации
        doc_btn_frame = ttk.Frame(help_frame)
        doc_btn_frame.pack(pady=10)
        ttk.Button(doc_btn_frame, text="Открыть guide.html", command=self._open_guide, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(doc_btn_frame, text="Открыть scheme.html", command=self._open_scene, width=20).pack(side=tk.LEFT, padx=5)

        ttk.Button(help_frame, text="Открыть справку программы", command=self.show_help, width=22).pack(padx=8, pady=8)

    def _open_guide(self):
        path = self._get_doc_path("guide.html")
        if path and os.path.exists(path):
            webbrowser.open(path)
        else:
            messagebox.showerror("Ошибка", f"Файл guide.html не найден по пути {path}")

    def _open_scene(self):
        path = self._get_doc_path("scheme.html")
        if path and os.path.exists(path):
            webbrowser.open(path)
        else:
            messagebox.showerror("Ошибка", f"Файл scheme.html не найден по пути {path}")

    def save_log(self, text_widget):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text_widget.get(1.0, tk.END))
                self.status_var.set("Лог сохранён")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")

    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Справка")
        help_window.geometry("800x700")
        help_window.transient(self.root)
        help_window.grab_set()
        try:
            help_window.iconbitmap(self._get_doc_path(os.path.join("images", "images.ico")))
        except Exception as e:
            print(f"[Gotcha] suppressed: {e}")
        help_notebook = ttk.Notebook(help_window)
        help_notebook.pack(fill='both', expand=True, padx=15, pady=15)
        general_frame = ttk.Frame(help_notebook)
        help_notebook.add(general_frame, text="Общая информация")
        general_text = """Gotcha – Инструмент для тестирования сетевой безопасности
https://github.com/hedromanie

ТРЕБОВАНИЯ:
• Права администратора
• Windows 10 21H2+ (или новее)
• WinDivert.dll + WinDivert64.sys рядом с exe (для TCP / UDP / ICMP)
• Установленный Npcap (для ARP / MAC flood и сниффинга)
• Wireshark рекомендуется для мониторинга трафика
• Для поиска уязвимостей: Nmap / Zenmap
• Для обучения: Metasploit / Kali / BlackArch

DoS (TCP/UDP/ICMP) работают через WinDivert — Npcap для них не нужен.
ARP и MAC flood по-прежнему используют Npcap (L2).

Если у вас возникли проблемы или вас не устраивает скорость DoS-атаки —
откройте корневую папку программы и найдите Guide.html.

Если не работает ARP spoofing / конфликт IP / жертва не достучится до шлюза,
в PowerShell:

Get-Service RemoteAccess
Set-Service RemoteAccess -StartupType Automatic
Start-Service RemoteAccess
"""
        general_txt = scrolledtext.ScrolledText(general_frame, wrap=tk.WORD, font=('Arial', 10))
        general_txt.pack(fill='both', expand=True, padx=10, pady=10)
        general_txt.insert('1.0', general_text)
        general_txt.config(state='disabled')
        bpf_frame = ttk.Frame(help_notebook)
        help_notebook.add(bpf_frame, text="BPF фильтры")
        bpf_text = """ПРИМЕРЫ BPF ФИЛЬТРОВ:
ОСНОВНЫЕ ПРИМИТИВЫ:
   host <ip>          – трафик с/на IP (host 192.168.1.1)
   net <сеть>         – трафик в сети (net 192.168.1.0/24)
   port <число>       – трафик на порт (port 80)
   portrange <min-max>– диапазон портов (portrange 1-1024)
   ether host <mac>   – кадры с указанным MAC
   ether broadcast    – широковещательные кадры
   ip, ip6, arp, tcp, udp, icmp – протоколы
НАПРАВЛЕНИЕ:
   src <примитив>     – только от источника
   dst <примитив>     – только к назначению
ЛОГИЧЕСКИЕ ОПЕРАТОРЫ:
   and, && – И
   or, ||  – ИЛИ
   not, !  – НЕ
ПРИМЕРЫ (с пояснениями):
   1. tcp port 80 – только TCP-пакеты с портом 80 (HTTP)
   2. udp port 53 – только DNS-запросы/ответы
   3. icmp – только ICMP (ping, ошибки)
   4. arp – только ARP-пакеты
   5. not arp and not stp and not cdp – исключает служебные протоколы (оставляет IP-трафик)
   6. host 192.168.1.100 and tcp port 22 – SSH-трафик с/на конкретный хост
   7. src net 192.168.1.0/24 – пакеты из сети 192.168.1.0/24
   8. tcp and (port 80 or port 443) – HTTP или HTTPS
   9. icmp or arp – диагностические протоколы
   10. not port 22 and not port 23 – исключает SSH и Telnet
   11. ether host 01:23:45:67:89:ab – кадры с заданным MAC
   12. vlan – все пакеты с тегом VLAN (можно уточнить vlan 100)
   13. greater 500 – пакеты длиннее 500 байт
   14. less 64 – короткие пакеты (<64 байт)
Примечание: фильтры нечувствительны к регистру;
Фильтры могут быть самыми разными не только теми, что указаны здесь"""
        bpf_txt = scrolledtext.ScrolledText(bpf_frame, wrap=tk.WORD, font=('Consolas', 9))
        bpf_txt.pack(fill='both', expand=True, padx=10, pady=10)
        bpf_txt.insert('1.0', bpf_text)
        bpf_txt.config(state='disabled')
        attacks_frame = ttk.Frame(help_notebook)
        help_notebook.add(attacks_frame, text="Описание атак")
        attacks_text = """АТАКИ:
1. ПЕРЕХВВАТ ПАКЕТОВ
   • Захватывает сетевой трафик на выбранном интерфейсе.
   • Можно указать BPF-фильтр для выборочного захвата.
   • При захвате программа автоматически отправляет заданное количество
     ответных пакетов (например, ICMP Echo Reply на Ping).
   • Позволяет сохранить перехваченный пакет, отредактировать его и отправить
     повторно.
   • Применяется для анализа трафика, тестирования сетевых устройств,
     изучения протоколов.
2. DHCP STARVATION (ИСЩЕНИЕ ПУЛА DHCP)
   • Атака по принципу DORA с уникальными MAC-адресами.
   • DHCP-сервер вынужден резервировать IP-адреса для каждого запроса,
     что приводит к исчерпанию пула доступных адресов.
   • Легитимные клиенты не могут получить IP.
   • Используется для проверки устойчивости DHCP-сервера.
3. DoS АТАКИ (ФЛУД)
   Поддерживаются протоколы: TCP, UDP, ICMP, ARP, DNS.
   • TCP SYN flood – TCP-пакеты с флагом SYN (WinDivert).
   • UDP flood – массовая отправка UDP (WinDivert).
   • ICMP flood – ICMP Echo Request (WinDivert).
   • ARP flood – ARP-запросы (Npcap, L2).
   • DNS flood – DNS Query UDP/53 (WinDivert / NPdnsT).
   • Для TCP/UDP/ICMP: опция случайного IP-источника.
   • Для ARP: случайный IP и/или MAC источника.
   • Число потоков настраивается (1–8).
4. ARP SPOOFING (ПОДМЕНА ARP)
   • Атака типа «человек посередине» на канальном уровне.
   • Отправляет поддельные ARP-ответы, убеждая целевое устройство и шлюз,
     что MAC-адрес атакующего принадлежит другому узлу.
   • Весь трафик между целью и шлюзом проходит через атакующего.
   • Возможно восстановление ARP после остановки и включение IP forwarding.
5. MAC FLOOD
   • Отправляет огромное количество Ethernet-кадров с минимальным размером
     и случайными MAC-адресами источника.
   • Переполняет таблицу коммутации (CAM-таблицу) коммутатора, заставляя его
     работать как хаб (ретранслировать весь трафик во все порты).
   • Может привести к отказу в обслуживании или раскрытию трафика.
6. DNS SPOOFING
   • Перехватывает DNS-запросы и подменяет ответы.
   • Позволяет перенаправлять трафик на заданный IP-адрес.
   • Поддерживает маски доменов (например, *.example.com) и catch-all правило."""
        attacks_txt = scrolledtext.ScrolledText(attacks_frame, wrap=tk.WORD, font=('Consolas', 9))
        attacks_txt.pack(fill='both', expand=True, padx=10, pady=10)
        attacks_txt.insert('1.0', attacks_text)
        attacks_txt.config(state='disabled')
        access_frame = ttk.Frame(help_notebook)
        help_notebook.add(access_frame, text="Доступ и диагностика")
        access_text = """ФУНКЦИИ ВКЛАДКИ "ДОСТУП":
1. ICMP Ping
   • Отправляет 4 ICMP Echo Request (ping) на указанный IP-адрес.
   • Использует системную утилиту ping, вывод отображается в логе.
   • Позволяет проверить доступность узла и измерить время отклика.
2. Port Scan
   • Сканирует наиболее распространённые TCP-порты (21,22,23,25,53,80,110,143,443,993,995,3389).
   • Для каждого порта выполняется попытка установить TCP-соединение.
   • Результат: список открытых портов.
3. Traceroute
   • Выполняет трассировку маршрута до указанного узла.
   • На Windows использует tracert с параметрами -d -h 30 -w 1000.
   • На Linux — traceroute -n -m 30 -w 1.
   • Показывает промежуточные узлы и задержки.
4. Таблица маршрутизации
   • Выводит IPv4 таблицу маршрутизации (аналог route print).
   • Отфильтровывает IPv6 строки для удобства чтения.
   • Полезна для диагностики сетевых настроек.
5. Сетевые адаптеры
   • Показывает все доступные сетевые интерфейсы (имена, IP-адреса, MAC-адреса).
6. Сканировать сеть
   • Выполняет ARP-сканирование локальной сети /24 (на основе введённого IP).
   • Отправляет ARP-запросы на все адреса подсети.
   • Через 2 секунды выводит список найденных устройств с IP, MAC и, при возможности, hostname.
   • Полезно для инвентаризации сети и обнаружения активных хостов."""
        access_txt = scrolledtext.ScrolledText(access_frame, wrap=tk.WORD, font=('Arial', 10))
        access_txt.pack(fill='both', expand=True, padx=10, pady=10)
        access_txt.insert('1.0', access_text)
        access_txt.config(state='disabled')
        close_btn = ttk.Button(help_window, text="Закрыть", command=help_window.destroy)
        close_btn.pack(pady=10)
        self.theme_manager.apply_to_widgets(help_window, self.theme_manager.themes[self.theme_manager.current_theme])

    def generate_random_mac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255)
        )

    def on_closing(self):
        if self.custom_attack_running:
            self.stop_custom_attack()
        if self.dhcp_attack_running:
            self.stop_dhcp_attack()
        if self.arp_spoof_running:
            self.stop_arp_spoof()
        if self.packet_intercept_running:
            self.stop_packet_intercept()
        if self.mac_attack_running:
            self.stop_mac_flood()
        if self.dns_spoof_running:
            self.stop_dns_spoof()
        # IP forwarding — вернуть только при выходе
        if getattr(self, "_ip_forward_saved", False):
            try:
                self.enable_ip_forward(False)
            except Exception as e:
                print(f"[Gotcha] forward restore: {e}")
        for key, (proc, stop_event) in list(self.external_processes.items()):
            stop_event.set()
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except Exception as e:
                    print(f"[Gotcha] error: {e}")
                    proc.kill()
        self.system_monitor_running = False
        self.root.destroy()
