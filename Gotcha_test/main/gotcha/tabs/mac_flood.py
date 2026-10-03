"""MAC flood tab (NPmac-aT)."""
import time
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from gotcha.utils import find_exe

class MacFloodTabMixin:
    # -------------------- MAC flood (Npcap, L2) --------------------
    def setup_mac_flood_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        params_frame = ttk.LabelFrame(left_frame, text="Параметры MAC flood")
        params_frame.pack(fill='x', padx=5, pady=5)
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.mac_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.mac_interface.pack(side='left', padx=2)
        self.mac_interface.set(self.active_interface)
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Время (сек):", width=12).pack(side='left', padx=2)
        self.mac_duration = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.mac_duration.pack(side='left', padx=2)
        self.mac_duration.insert(0, "60")
        ttk.Label(row3, text="(0=бесконечно)").pack(side='left', padx=5)
        row_threads = ttk.Frame(params_frame)
        row_threads.pack(fill='x', padx=5, pady=5)
        ttk.Label(row_threads, text="Потоки:", width=12).pack(side='left', padx=2)
        self.mac_threads = ttk.Entry(row_threads, width=10, font=('Arial', 9))
        self.mac_threads.pack(side='left', padx=2)
        self.mac_threads.insert(0, "4")
        ttk.Label(row_threads, text="1–8").pack(side='left', padx=6)
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="MAC назначения:", width=12).pack(side='left', padx=2)
        self.mac_dst = ttk.Entry(row4, width=25, font=('Arial', 9))
        self.mac_dst.pack(side='left', padx=2)
        self.mac_dst.insert(0, "ff:ff:ff:ff:ff:ff")
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        self.mac_random = tk.BooleanVar(value=False)
        ttk.Checkbutton(row5, text="Случайный MAC источника", variable=self.mac_random).pack(side='left', padx=5)
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        self.mac_start_btn = ttk.Button(button_frame, text="Начать MAC flood",
                                        command=self.start_mac_flood, width=18)
        self.mac_start_btn.pack(side='left', padx=5)
        self.mac_stop_btn = ttk.Button(button_frame, text="Остановить",
                                       command=self.stop_mac_flood, width=15, state='disabled')
        self.mac_stop_btn.pack(side='left', padx=5)
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        ttk.Label(stats_grid, text="Отправлено кадров:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.mac_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Скорость (fps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.mac_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.mac_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.mac_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.mac_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        log_frame = ttk.LabelFrame(right_frame, text="Лог MAC flood")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.mac_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.mac_log.pack(fill='both', expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог",
                  command=lambda: self.save_log(self.mac_log), width=14).pack()
        self.mac_stats = {'start_time': 0, 'sent_frames': 0}

    def start_mac_flood(self):
        if self.mac_attack_running:
            return
        self.mac_attack_running = True
        self.mac_start_btn.config(state='disabled')
        self.mac_stop_btn.config(state='normal')
        try:
            interface = self.mac_interface.get()
            duration = int(self.mac_duration.get())
            threads = int(self.mac_threads.get().strip())
            if threads < 1 or threads > 8:
                raise ValueError("Потоки: 1–8")
            dst_mac = self.mac_dst.get().strip()
            random_mac = self.mac_random.get()
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Проверьте введённые данные\n{e}")
            self.mac_attack_running = False
            self.mac_start_btn.config(state='normal')
            return
        exe_path = find_exe("NPmac-aT.exe")
        if not exe_path:
            self.mac_log.insert('end', "Error: NPmac-aT.exe not found. Положите exe в main/bin или переустановите Gotcha!\n")
            self.mac_attack_running = False
            self.mac_start_btn.config(state='normal')
            return
        # NPmac-aT: <interface|auto> <threads> <duration> [dst_mac] [--random-mac]
        args = [exe_path, interface, str(threads), str(duration)]
        if dst_mac:
            args.append(dst_mac)
        if random_mac:
            args.append("--random-mac")
        self.mac_log.delete(1.0, tk.END)
        self.mac_log.insert('end', f"MAC flood started\n")
        self.mac_log.insert('end', f"Interface: {interface}\n")
        self.mac_log.insert('end', f"Threads: {threads}\n")
        self.mac_log.insert('end', f"Duration: {duration} sec\n")
        self.mac_log.insert('end', f"Dest MAC: {dst_mac}\n")
        self.mac_log.insert('end', f"Random source MAC: {'yes' if random_mac else 'no'}\n")
        self.mac_stop_event = threading.Event()
        def mac_stats_callback(data):
            if not self.mac_attack_running:
                return
            packets = data.get('packets', 0)
            pps = data.get('pps', 0)
            elapsed = data.get('time', 0)
            self.mac_sent.config(text=str(packets))
            self.mac_rate.config(text=str(pps))
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            self.mac_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        self.mac_external_thread = threading.Thread(
            target=self.run_external_tool,
            args=(args, self.mac_log, self.mac_stop_event, 'mac'),
            kwargs={'infinite': (duration == 0), 'on_finish': self.on_mac_finished, 'stats_callback': mac_stats_callback},
            daemon=True
        )
        self.mac_external_thread.start()
        self.mac_stats = {'start_time': time.time(), 'sent_frames': 0}
        self.status_var.set("MAC flood started")

    def stop_mac_flood(self):
        if not self.mac_attack_running:
            return
        proc_info = self.external_processes.get('mac')
        if proc_info:
            proc, stop_event = proc_info
            stop_event.set()
            if proc.poll() is None:
                try:
                    proc.stdin.write('\n')
                    proc.stdin.flush()
                except Exception as e:
                    print(f"[Gotcha] suppressed: {e}")
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self.mac_attack_running = False
        self.mac_start_btn.config(state='normal')
        self.mac_stop_btn.config(state='disabled')
        self.status_var.set("MAC flood stopped")

    def on_mac_finished(self):
        self.mac_attack_running = False
        self.mac_start_btn.config(state='normal')
        self.mac_stop_btn.config(state='disabled')

