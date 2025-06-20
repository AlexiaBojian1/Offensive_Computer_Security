import Tkinter as tk
import ttk
import threading
import subprocess
from scapy.all import get_if_list
import os

class SSLStripUI(tk.Tk):
    def __init__(self):
        # Initialize base Tk class explicitly (avoids super() issues in Python 2)
        tk.Tk.__init__(self)
        self.title("SSL Strip Tool UI")
        self.process = None

        # Interface selection
        tk.Label(self, text="Interface:").grid(row=0, column=0, sticky='e')
        self.iface_var = tk.StringVar()
        ifaces = get_if_list()
        self.iface_combo = ttk.Combobox(self, textvariable=self.iface_var, values=ifaces)
        self.iface_combo.grid(row=0, column=1, padx=5, pady=5)

        # BPF filter entry
        tk.Label(self, text="BPF Filter:").grid(row=1, column=0, sticky='e')
        self.bpf_entry = tk.Entry(self)
        # Leave blank to use default tcp port 80
        self.bpf_entry.insert(0, '')
        self.bpf_entry.grid(row=1, column=1, padx=5, pady=5)

        # Host filter entry
        tk.Label(self, text="Hosts (CSV wildcards):").grid(row=2, column=0, sticky='e')
        self.hosts_entry = tk.Entry(self)
        self.hosts_entry.grid(row=2, column=1, padx=5, pady=5)

        # Verbose / Quiet toggles
        self.verbose_var = tk.BooleanVar()
        self.quiet_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Verbose (-v)", variable=self.verbose_var,
                       command=self.on_verbose_toggle).grid(row=3, column=0)
        tk.Checkbutton(self, text="Quiet (-q)", variable=self.quiet_var,
                       command=self.on_quiet_toggle).grid(row=3, column=1)

        # Control buttons
        self.start_btn = tk.Button(self, text="Start", command=self.start_strip)
        self.start_btn.grid(row=4, column=0, padx=5, pady=10)
        self.stop_btn = tk.Button(self, text="Stop", state='disabled', command=self.stop_strip)
        self.stop_btn.grid(row=4, column=1, padx=5, pady=10)

        # Log display
        self.log_text = tk.Text(self, height=15, width=60)
        self.log_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        scrollbar = tk.Scrollbar(self, command=self.log_text.yview)
        scrollbar.grid(row=5, column=2, sticky='nsew')
        self.log_text['yscrollcommand'] = scrollbar.set

    def on_verbose_toggle(self):
        if self.verbose_var.get():
            self.quiet_var.set(False)

    def on_quiet_toggle(self):
        if self.quiet_var.get():
            self.verbose_var.set(False)

    def start_strip(self):
        iface = self.iface_var.get().strip()
        bpf = self.bpf_entry.get().strip()
        hosts = self.hosts_entry.get().strip()
        verbose = self.verbose_var.get()
        quiet = self.quiet_var.get()

        if not iface:
            self._log("Error: Interface must be selected.\n")
            return

        # Build ssl.py command
        script_path = os.path.join(os.path.dirname(__file__), '..', 'protocols', 'ssl.py')
        args = ['sudo', 'python2', script_path, '-i', iface]
        if bpf:
            args += ['--bpf', bpf]
        if hosts:
            args += ['--hosts', hosts]
        if verbose:
            args.append('-v')
        elif quiet:
            args.append('-q')

        # Try launching in terminal emulator
        term = os.environ.get('TERMINAL', 'xterm')
        term_cmd = [term, '-hold', '-e'] + args
        try:
            cmd_str = subprocess.list2cmdline(term_cmd)
            self._log("Launching in terminal: %s\n" % cmd_str)
            self.process = subprocess.Popen(term_cmd)
            # Monitor exit
            def wait_term():
                self.process.wait()
                self._on_end()
            t_term = threading.Thread(target=wait_term)
            t_term.daemon = True
            t_term.start()
        except (OSError, AttributeError):
            # Terminal not found or list2cmdline missing: fallback to in-GUI logging
            self._log("Terminal launch failed; running inline.\n")
            self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # Read output into GUI
            def run_proc():
                for raw in self.process.stdout:
                    try:
                        line = raw.decode('utf-8')
                    except:
                        line = str(raw)
                    self._log(line)
                self._on_end()
            t = threading.Thread(target=run_proc)
            t.daemon = True
            t.start()

        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

    def stop_strip(self):
        if self.process:
            self.process.terminate()
            self._log("\nStopped SSL strip.\n")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

    def _on_end(self):
        self._log("\nProcess ended.\n")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.process = None

    def _log(self, msg):
        self.log_text.insert(tk.END, msg)
        self.log_text.see(tk.END)

if __name__ == '__main__':
    app = SSLStripUI()
    app.mainloop()