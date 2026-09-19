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
SCRIPT_DIR = Path(__file__).resolve().parent
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
DRIVERS_DIR = SYSTEM32 / "drivers"

DLL_FILES = ["wpcap.dll", "packet.dll"]
DRIVER_FILES = ["npf.sys"]

# В режиме совместимости служба называется npf, а не npcap
SERVICE_NAMES = ["npf", "npcap"]  # удаляем обе на всякий случай

# Возможные имена файлов установщика Npcap
NPF_INSTALL_CANDIDATES = ["NPFInstall.exe"]


# ---------------------------------------------------------------------------
# Права администратора
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin() -> None:
    script = os.path.abspath(__file__)
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    if ret <= 32:
        print("[!] Не удалось получить права администратора. Код:", ret)
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


def run(cmd: list, timeout: int = 60) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
    # npf.sys не обязателен, но полезен — предупредим, если нет
    if not (SCRIPT_DIR / "npf.sys").is_file():
        print("[~] Предупреждение: рядом нет npf.sys — NPFInstall может его не найти.")
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

    print(f"[*] Установка драйвера: {exe.name} -i ...")
    r = run([str(exe), "-i"], timeout=120)
    if r is None:
        sys.exit(1)

    if r.stdout.strip():
        print("    STDOUT:", r.stdout.strip())
    if r.stderr.strip():
        print("    STDERR:", r.stderr.strip())

    if r.returncode != 0:
        print(f"    [!] NPFInstall вернул код {r.returncode}. Проверьте антивирус и другие NDIS-фильтры.")
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
    print("[*] Проверка службы npf...")
    r = run(["sc", "query", "npf"])
    if r is None:
        return
    out = r.stdout.strip()
    if "RUNNING" in out:
        print("    [+] Служба npf работает (RUNNING).")
    elif "STOPPED" in out:
        print("    [~] Служба npf создана, но остановлена. Пробуем запустить...")
        run(["sc", "start", "npf"])
    else:
        print("    [?] Ответ sc query npf:")
        print(out)


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

    print(f"[*] Удаление драйвера через {exe.name} -u ...")
    r = run([str(exe), "-u"], timeout=120)
    if r is None:
        return
    if r.stdout.strip():
        print("    STDOUT:", r.stdout.strip())
    if r.stderr.strip():
        print("    STDERR:", r.stderr.strip())
    if r.returncode == 0:
        print("    [+] Штатное удаление драйвера успешно.")
    else:
        print(f"    [~] NPFInstall вернул код {r.returncode} (это нормально, если драйвер уже был удалён).")


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
def print_menu() -> str:
    print("=" * 60)
    print(" Npcap WinPcap-compatible — управление установкой")
    print("=" * 60)
    print("  1 — Установить")
    print("  2 — Удалить")
    print("  0 — Выход")
    print("=" * 60)
    return input("Выберите действие [0/1/2]: ").strip()


def main() -> None:
    # Разбор аргументов командной строки
    args = sys.argv[1:]
    mode = None
    if "--install" in args:
        mode = "install"
    elif "--uninstall" in args:
        mode = "uninstall"
    elif args and args[0].isdigit():
        mode = {"1": "install", "2": "uninstall", "0": "exit"}.get(args[0])

    # Если прав нет — перезапускаемся с UAC
    if not is_admin():
        print("[*] Запрашиваем права администратора...")
        relaunch_as_admin()
        return  # сюда управление не вернётся

    if mode is None:
        choice = print_menu()
        mode = {"1": "install", "2": "uninstall", "0": "exit"}.get(choice)
        if mode is None:
            print("[!] Неверный выбор.")
            sys.exit(1)

    if mode == "install":
        do_install()
    elif mode == "uninstall":
        do_uninstall()
    else:
        sys.exit(0)

    input("\nНажмите Enter для выхода...")


if __name__ == "__main__":
    main()