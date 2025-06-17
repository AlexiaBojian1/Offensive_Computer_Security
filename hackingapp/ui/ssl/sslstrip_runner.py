import threading
import subprocess
import time

class SSLStripRunner:
    def __init__(self, log_callback):
        self._thread = None
        self._running = False
        self._iface = ""
        self._log_callback = log_callback

    def setInterface(self, iface: str):
        self._iface = iface

    def start(self):
        if self._running:
            self._log_callback("SSLStrip already running.")
            return

        def run():
            self._running = True
            self._log_callback(f"Starting SSLStrip on interface {self._iface}")
            try:
                proc = subprocess.Popen(
                    ["python3", "sslstrip.py", "-i", self._iface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                while self._running and proc.poll() is None:
                    line = proc.stdout.readline()
                    if line:
                        self._log_callback(line.strip())
                proc.terminate()
            except Exception as e:
                self._log_callback(f"Error: {e}")
            finally:
                self._log_callback("SSLStrip stopped.")
                self._running = False

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
