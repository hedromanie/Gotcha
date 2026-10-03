#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gotcha entry point."""
import sys
import os
import platform
import subprocess
import tkinter as tk
import ctypes

# Allow "main/" as script dir and project root on path
_MAIN_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_MAIN_DIR)
if _MAIN_DIR not in sys.path:
    sys.path.insert(0, _MAIN_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from gotcha.app import Gotcha
from gotcha.utils import check_admin, relaunch_as_admin


def main():
    if platform.system() == "Windows" and not check_admin():
        if not relaunch_as_admin():
            try:
                ctypes.windll.user32.MessageBoxW(
                    None,
                    "Не удалось получить права администратора.\nЗапустите Gotcha от имени администратора.",
                    "Gotcha",
                    0x10,
                )
            except Exception:
                pass
        sys.exit(0)

    try:
        flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        subprocess.run(
            ["powershell", "-Command",
             "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' "
             "-Name 'IPEnableRouter' -Value 1"],
            capture_output=True, creationflags=flags,
        )
        subprocess.run(
            ["powershell", "-Command", "Set-Service RemoteAccess -StartupType Automatic"],
            capture_output=True, creationflags=flags,
        )
        subprocess.run(
            ["powershell", "-Command", "Start-Service RemoteAccess"],
            capture_output=True, creationflags=flags,
        )
    except Exception:
        pass

    root = tk.Tk()
    app = Gotcha(root)
    app.show_initial_warning()
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
