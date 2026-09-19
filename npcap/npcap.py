#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install_npcap_compat.py
Установка / удаление Npcap в режиме совместимости с WinPcap.

Установка:
    python install_npcap_compat.py            # интерактивное меню
    python install_npcap_compat.py --install  # сразу установка
    python install_npcap_compat.py --uninstall# сразу удаление

Файлы wpcap.dll, packet.dll, NPFInstall.exe и npf.sys должны лежать рядом со скриптом.
"""

import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path

# --- Константы ---
def _app_dir() -> Path:
    """Папка с exe (PyInstaller) или со скриптом. Рядом лежат DLL/NPFInstall."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


SCRIPT_DIR = _app_dir()
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
DRIVERS_DIR = SYSTEM32 / "drivers"

DLL_FILES = ["wpcap.dll", "packet.dll"]
# В бандле может быть npf.sys или npcap.sys
DRIVER_FILES = ["npf.sys", "npcap.sys"]

SERVICE_NAMES = ["npf", "npcap"]
NPF_INSTALL_CANDIDATES = ["NPFInstall.exe"]


def has_console() -> bool:
    """False при сборке --noconsole или если stdin недоступен."""
    try:
        if sys.stdin is None or not hasattr(sys.stdin, "isatty"):
            return False
        return bool(sys.stdin.isatty())
    except Exception:
        return False


def msgbox(text: str, title: str = "Gotcha Npcap", flags: int = 0x40) -> int:
    """MessageBox (MB_OK | icon). flags: 0x40=info, 0x10=error, 0x24=yes/no+question."""
    try:
        return int(ctypes.windll.user32.MessageBoxW(None, text, title, flags))
    except Exception:
        return 0


def safe_pause(msg: str = "Done.") -> None:
    if has_console():
        try:
            input(f"\n{msg} Press Enter to exit...")
        except Exception:
            pass
    else:
        msgbox(msg, "Gotcha Npcap", 0x40)


# ---------------------------------------------------------------------------
# Права администратора
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """UAC: для frozen — сам exe; для .py — python + скрипт."""
    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        executable = sys.executable
        script = os.path.abspath(sys.argv[0])
        rest = " ".join(f'"{a}"' for a in sys.argv[1:])
        params = f'"{script}" {rest}'.strip()
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, params, None, 1
    )
    if ret <= 32:
        msgbox(f"Failed to elevate (code {ret}). Run as Administrator.", "Gotcha Npcap", 0x10)
        sys.exit(1)
    sys.exit(0)


# ---------------------------------------------------------------------------
# Вспомогательное
# ---------------------------------------------------------------------------
def find_npf_install() -> Path | None:
    for name in NPF_INSTALL_CANDIDATES:
        p = SCRIPT_DIR / name
        if p.is_file():
            return p
    return None


def run(cmd: list, timeout: int = 60, cwd: Path | None = None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except subprocess.TimeoutExpired:
        print(f"    [!] Команда зависла: {' '.join(cmd)}")
    except Exception as e:
        print(f"    [!] Ошибка запуска {' '.join(cmd)}: {e}")
    return None


def service_exists(name: str) -> bool:
    r = run(["sc", "query", name])
    return r is not None and r.returncode == 0


def stop_and_delete_service(name: str) -> bool:
    """Останавливает и удаляет службу. Возвращает True, если что-то было сделано."""
    if not service_exists(name):
        print(f"    [~] Служба {name} не найдена.")
        return False

    print(f"    [*] Останавливаем службу {name}...")
    run(["sc", "stop", name])

    print(f"    [*] Удаляем службу {name}...")
    r = run(["sc", "delete", name])
    if r and r.returncode == 0:
        print(f"    [+] Служба {name} удалена.")
    else:
        print(f"    [!] Не удалось удалить службу {name}.")
    return True


# ---------------------------------------------------------------------------
# УСТАНОВКА
# ---------------------------------------------------------------------------
def check_files_install() -> None:
    missing = []
    for name in DLL_FILES + ["NPFInstall.exe"]:
        if not (SCRIPT_DIR / name).is_file():
            missing.append(name)
    if not any((SCRIPT_DIR / n).is_file() for n in DRIVER_FILES):
        print("[~] Warning: no npf.sys / npcap.sys next to the exe — NPFInstall may fail.")
    if missing:
        print("[!] Не найдены следующие файлы рядом со скриптом:")
        for m in missing:
            print(f"    - {m}")
        print("\nПоложите их в папку:", SCRIPT_DIR)
        sys.exit(1)


def copy_dlls() -> None:
    print("[*] Копирование DLL в System32...")
    for name in DLL_FILES:
        src = SCRIPT_DIR / name
        dst = SYSTEM32 / name
        try:
            shutil.copy2(src, dst)
            print(f"    [+] {name} -> {dst}")
        except PermissionError:
            print(f"    [!] Нет доступа к {dst}. Запустите от админа.")
            sys.exit(1)
        except Exception as e:
            print(f"    [!] Ошибка копирования {name}: {e}")
            sys.exit(1)


def install_driver() -> None:
    exe = find_npf_install()
    if not exe:
        print("[!] NPFInstall.exe не найден рядом со скриптом.")
        sys.exit(1)

    # NPFInstall ищет .sys/.inf/.cat в cwd — всегда работаем из SCRIPT_DIR
    print(f"[*] Установка драйвера: {exe.name} -i")
    print(f"    cwd = {SCRIPT_DIR}")
    r = run([str(exe), "-i"], timeout=120, cwd=SCRIPT_DIR)
    if r is None:
        sys.exit(1)

    if r.stdout and r.stdout.strip():
        print("    STDOUT:", r.stdout.strip())
    if r.stderr and r.stderr.strip():
        print("    STDERR:", r.stderr.strip())

    if r.returncode != 0:
        print(f"    [!] NPFInstall вернул код {r.returncode}. Проверьте антивирус и NDIS-фильтры.")
        sys.exit(1)
    print("    [+] Драйвер установлен.")


def set_registry_compat_flag() -> None:
    print("[*] Установка флага WinPcapCompatible в реестре...")
    import winreg

    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
    ]
    for hive, path in keys:
        try:
            key = winreg.CreateKeyEx(hive, path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "WinPcapCompatible", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            print(f"    [+] HKLM\\{path}\\WinPcapCompatible = 1")
        except PermissionError:
            print(f"    [!] Нет доступа к HKLM\\{path}")
        except Exception as e:
            print(f"    [!] Ошибка записи в HKLM\\{path}: {e}")


def verify_install() -> None:
    print("[*] Проверка служб npf / npcap...")
    found = False
    for name in SERVICE_NAMES:
        r = run(["sc", "query", name])
        if r is None:
            continue
        out = (r.stdout or "").strip()
        if r.returncode != 0 and "FAILED" in out.upper():
            print(f"    [~] {name}: не найдена")
            continue
        found = True
        if "RUNNING" in out:
            print(f"    [+] Служба {name}: RUNNING")
        elif "STOPPED" in out:
            print(f"    [~] Служба {name}: STOPPED — start...")
            run(["sc", "start", name])
        else:
            print(f"    [?] sc query {name}:\n{out}")
    if not found:
        print("    [!] Ни npf, ни npcap не найдены после установки.")


def do_install() -> None:
    print("=" * 60)
    print(" УСТАНОВКА Npcap в режиме совместимости с WinPcap")
    print("=" * 60)
    print(f" Папка со скриптом: {SCRIPT_DIR}")
    print(f" System32:          {SYSTEM32}")
    print("=" * 60)

    check_files_install()
    copy_dlls()
    install_driver()
    set_registry_compat_flag()
    verify_install()

    print("\n[✓] Установка завершена. Рекомендуется перезагрузить систему.")


# ---------------------------------------------------------------------------
# УДАЛЕНИЕ
# ---------------------------------------------------------------------------
def uninstall_driver() -> None:
    """Пытается удалить драйвер штатной утилитой NPFInstall.exe -u."""
    exe = find_npf_install()
    if not exe:
        print("[~] NPFInstall.exe не найден — пропускаем штатное удаление драйвера.")
        return
    print(f"[*] Удаление драйвера: {exe.name} -u (cwd={SCRIPT_DIR})")
    r = run([str(exe), "-u"], timeout=120, cwd=SCRIPT_DIR)
    if r is None:
        return
    if r.stdout and r.stdout.strip():
        print("    STDOUT:", r.stdout.strip())
    if r.stderr and r.stderr.strip():
        print("    STDERR:", r.stderr.strip())
    if r.returncode == 0:
        print("    [+] Штатное удаление драйвера успешно.")
    else:
        print(f"    [~] NPFInstall -u code {r.returncode} (нормально, если драйвер уже снят).")


def remove_services() -> None:
    print("[*] Удаление служб драйвера...")
    for name in SERVICE_NAMES:
        stop_and_delete_service(name)


def remove_dlls() -> None:
    print("[*] Удаление DLL из System32...")
    for name in DLL_FILES:
        p = SYSTEM32 / name
        if not p.exists():
            print(f"    [~] {p} уже отсутствует.")
            continue
        try:
            p.unlink()
            print(f"    [+] Удалён {p}")
        except PermissionError:
            print(f"    [!] Нет доступа к {p} (возможно, файл занят).")
        except Exception as e:
            print(f"    [!] Ошибка удаления {p}: {e}")


def remove_driver_files() -> None:
    print("[*] Удаление .sys из drivers...")
    for name in DRIVER_FILES:
        p = DRIVERS_DIR / name
        if not p.exists():
            print(f"    [~] {p} уже отсутствует.")
            continue
        try:
            p.unlink()
            print(f"    [+] Удалён {p}")
        except PermissionError:
            print(f"    [!] Нет доступа к {p} (возможно, драйвер всё ещё загружен, нужна перезагрузка).")
        except Exception as e:
            print(f"    [!] Ошибка удаления {p}: {e}")


def remove_registry_compat_flag() -> None:
    print("[*] Удаление ключа WinPcapCompatible и ветки Npcap...")
    import winreg

    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
    ]
    for hive, path in paths:
        try:
            # Пытаемся открыть на удаление
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
            except FileNotFoundError:
                print(f"    [~] HKLM\\{path} не существует.")
                continue

            # Удаляем значение WinPcapCompatible, если есть
            try:
                winreg.DeleteValue(key, "WinPcapCompatible")
                print(f"    [+] HKLM\\{path}\\WinPcapCompatible удалён.")
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)

            # Пытаемся удалить саму ветку (если пуста)
            try:
                winreg.DeleteKey(hive, path)
                print(f"    [+] Ветка HKLM\\{path} удалена.")
            except OSError:
                print(f"    [~] Ветка HKLM\\{path} не пуста — оставлена.")
        except PermissionError:
            print(f"    [!] Нет доступа к HKLM\\{path}")
        except Exception as e:
            print(f"    [!] Ошибка при удалении HKLM\\{path}: {e}")


def do_uninstall() -> None:
    print("=" * 60)
    print(" УДАЛЕНИЕ Npcap (режим совместимости с WinPcap)")
    print("=" * 60)
    print(f" System32: {SYSTEM32}")
    print("=" * 60)

    uninstall_driver()   # штатное -u, если возможно
    remove_services()    # подстраховка: sc delete npf / npcap
    remove_dlls()
    remove_driver_files()
    remove_registry_compat_flag()

    print("\n[✓] Удаление завершено. Рекомендуется перезагрузить систему.")
    print("    Если npf.sys не удалился — перезагрузитесь и запустите скрипт ещё раз.")


# ---------------------------------------------------------------------------
# МЕНЮ И ТОЧКА ВХОДА
# ---------------------------------------------------------------------------
# МЕНЮ И ТОЧКА ВХОДА
# ---------------------------------------------------------------------------
def choose_mode_interactive():
    """Консоль или MessageBox. Возвращает install / uninstall / exit."""
    if has_console():
        print("=" * 60)
        print(" Npcap WinPcap-compatible — install helper")
        print("=" * 60)
        print("  1 — Install")
        print("  2 — Uninstall")
        print("  0 — Exit")
        print("=" * 60)
        try:
            choice = input("Choose [0/1/2]: ").strip()
        except Exception:
            choice = "1"
        return {"1": "install", "2": "uninstall", "0": "exit"}.get(choice)

    # MB_YESNOCANCEL | MB_ICONQUESTION = 0x23
    r = msgbox(
        "Gotcha Npcap helper\n\n"
        "Yes = Install (WinPcap-compatible)\n"
        "No = Uninstall\n"
        "Cancel = Exit\n\n"
        "Tip: use --install or --uninstall to skip this dialog.",
        "Gotcha Npcap",
        0x23,
    )
    if r == 6:
        return "install"
    if r == 7:
        return "uninstall"
    return "exit"


def main() -> None:
    args = sys.argv[1:]
    mode = None
    if "--install" in args:
        mode = "install"
    elif "--uninstall" in args:
        mode = "uninstall"
    elif args and args[0].isdigit():
        mode = {"1": "install", "2": "uninstall", "0": "exit"}.get(args[0])

    if not is_admin():
        if has_console():
            print("[*] Requesting Administrator...")
        relaunch_as_admin()
        return

    if mode is None:
        mode = choose_mode_interactive()
        if mode is None:
            if has_console():
                print("[!] Invalid choice.")
            else:
                msgbox("Invalid choice.", "Gotcha Npcap", 0x10)
            sys.exit(1)

    # Пауза только если пользователь зашёл через меню (без --install/--uninstall)
    interactive = "--install" not in args and "--uninstall" not in args
    try:
        if mode == "install":
            do_install()
            safe_pause("Install finished.", force=interactive)
        elif mode == "uninstall":
            do_uninstall()
            safe_pause("Uninstall finished. Reboot recommended.", force=interactive)
        else:
            sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        if has_console():
            print(f"[!] Fatal: {e}")
        else:
            msgbox(f"Error:\n{e}", "Gotcha Npcap", 0x10)
        sys.exit(1)


if __name__ == "__main__":
    main()
