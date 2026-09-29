"""Shared helpers for Gotcha."""
import os
import sys
import platform
import ctypes

"""Shared helpers for Gotcha."""
import os
import sys
import platform
import ctypes


def find_exe(exe_name):
    if getattr(sys, "frozen", False):
        bases = [os.path.dirname(sys.executable), os.getcwd()]
    else:
        here = os.path.dirname(os.path.abspath(__file__))  # gotcha/
        main_dir = os.path.dirname(here)                     # main/
        project_dir = os.path.dirname(main_dir)              # Gotcha_test/
        bases = [main_dir, project_dir, os.getcwd(), here]

    search_paths = []
    for b in bases:
        search_paths.extend([
            os.path.join(b, "bin", exe_name),
            os.path.join(b, "main", "bin", exe_name),
            os.path.join(b, exe_name),
        ])
    for path in search_paths:
        if os.path.isfile(path):
            return path
    return None


def check_admin():
    if platform.system() != "Windows":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """UAC relaunch. For .py — python + script; for frozen — exe."""
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
    return ret > 32
