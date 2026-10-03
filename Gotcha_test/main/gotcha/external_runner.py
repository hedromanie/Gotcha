"""Run external attack binaries with thread-safe logging."""
import threading
import time
import subprocess
import platform
import json

class ExternalRunnerMixin:
    def _append_log(self, log_widget, text):
        """Безопасная запись в ScrolledText из любого потока."""
        def _do():
            try:
                log_widget.insert("end", text)
                log_widget.see("end")
            except Exception as e:
                print(f"[Gotcha] log append failed: {e}")
        try:
            self.root.after(0, _do)
        except Exception as e:
            print(f"[Gotcha] root.after failed: {e}")

    def run_external_tool(self, args, log_widget, stop_event, process_key, infinite=False, on_finish=None, stats_callback=None):
        try:
            popen_kwargs = dict(
                args=args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE if infinite else None,
                text=True,
                bufsize=1,
            )
            if platform.system() == "Windows":
                popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            proc = subprocess.Popen(**popen_kwargs)
            self.external_processes[process_key] = (proc, stop_event)
            for line in iter(proc.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("type") == "stats":
                        if stats_callback:
                            self.root.after(0, stats_callback, data)
                        elapsed = data.get("time", 0)
                        pps = data.get("pps", 0)
                        packets = data.get("packets", 0)
                        self._append_log(log_widget, f"{elapsed}s: {pps} pps (total: {packets})\n")
                    else:
                        self._append_log(log_widget, line + "\n")
                except json.JSONDecodeError:
                    self._append_log(log_widget, line + "\n")
                if stop_event.is_set():
                    if infinite and proc.poll() is None:
                        try:
                            proc.stdin.write("\n")
                            proc.stdin.flush()
                        except Exception as e:
                            print(f"[Gotcha] stop via stdin failed: {e}")
                            try:
                                proc.terminate()
                            except Exception as e2:
                                print(f"[Gotcha] terminate failed: {e2}")
                    else:
                        try:
                            proc.terminate()
                        except Exception as e:
                            print(f"[Gotcha] terminate failed: {e}")
                    break
            proc.wait()
        except Exception as e:
            self._append_log(log_widget, f"External process error: {e}\n")
            print(f"[Gotcha] run_external_tool: {e}")
        finally:
            self.external_processes.pop(process_key, None)
            self._append_log(log_widget, "External process finished.\n")
            if on_finish:
                try:
                    self.root.after(0, on_finish)
                except Exception as e:
                    print(f"[Gotcha] on_finish schedule failed: {e}")

