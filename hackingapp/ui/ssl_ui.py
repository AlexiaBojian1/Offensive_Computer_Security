#!/usr/bin/env python2
# -*- coding: utf-8 -*-

try:
    import Tkinter as tk
    import ttk
except ImportError:
    import tkinter as tk
    from tkinter import ttk

# Python 2: Queue; Python 3: queue
try:
    import Queue as queue
except ImportError:
    import queue

import threading
import subprocess
from scapy.all import get_if_list
import os
from datetime import datetime

class SSLStripUI(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("SSL Strip Tool UI")
        self.process = None

        # thread-safe queue for log lines
        self._line_queue = queue.Queue()
        self.after(100, self._poll_log_queue)

        # --- Interface picker ---
        tk.Label(self, text="Interface:").grid(row=0, column=0, sticky='e')
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(self, textvariable=self.iface_var,
                                        values=get_if_list())
        self.iface_combo.grid(row=0, column=1, padx=5, pady=5)

        # --- BPF filter ---
        tk.Label(self, text="BPF Filter:").grid(row=1, column=0, sticky='e')
        self.bpf_entry = tk.Entry(self)
        self.bpf_entry.insert(0, '')
        self.bpf_entry.grid(row=1, column=1, padx=5, pady=5)

        # --- Host filter ---
        tk.Label(self, text="Hosts (CSV wildcards):").grid(row=2, column=0, sticky='e')
        self.hosts_entry = tk.Entry(self)
        self.hosts_entry.grid(row=2, column=1, padx=5, pady=5)

        # --- Verbose / Quiet ---
        self.verbose_var = tk.BooleanVar()
        self.quiet_var   = tk.BooleanVar()
        tk.Checkbutton(self, text="Verbose (-v)", variable=self.verbose_var,
                       command=self.on_verbose_toggle).grid(row=3, column=0)
        tk.Checkbutton(self, text="Quiet (-q)",   variable=self.quiet_var,
                       command=self.on_quiet_toggle).grid(row=3, column=1)

        # --- Start / Stop buttons ---
        self.start_btn = tk.Button(self, text="Start", command=self.start_strip)
        self.start_btn.grid(row=4, column=0, padx=5, pady=10)
        self.stop_btn  = tk.Button(self, text="Stop", state='disabled',
                                   command=self.stop_strip)
        self.stop_btn.grid(row=4, column=1, padx=5, pady=10)

        # --- Log text area ---
        self.log_text = tk.Text(self, height=15, width=60)
        self.log_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        sb = tk.Scrollbar(self, command=self.log_text.yview)
        sb.grid(row=5, column=2, sticky='nsew')
        self.log_text['yscrollcommand'] = sb.set

    def on_verbose_toggle(self):
        if self.verbose_var.get():
            self.quiet_var.set(False)

    def on_quiet_toggle(self):
        if self.quiet_var.get():
            self.verbose_var.set(False)

    def start_strip(self):
        iface   = self.iface_var.get().strip()
        bpf     = self.bpf_entry.get().strip()
        hosts   = self.hosts_entry.get().strip()
        verbose = self.verbose_var.get()
        quiet   = self.quiet_var.get()

        if not iface:
            self._log("Error: Interface must be selected.\n")
            return

        # build ssl.py invocation
        script_path = os.path.join(os.path.dirname(__file__),
                                   '..', 'protocols', 'ssl.py')
        args = ['sudo', 'python2', '-u', script_path, '-i', iface]
        if bpf:    args += ['--bpf', bpf]
        if hosts:  args += ['--hosts', hosts]
        if verbose:
            args.append('-v')
        elif quiet:
            args.append('-q')

        # show the command we launched
        try:
            cmd_str = subprocess.list2cmdline(args)
        except AttributeError:
            cmd_str = ' '.join(args)
        self._log("Starting: %s\n" % cmd_str)

        # spawn it in completely unbuffered binary mode
        self.process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0
        )

        # reader thread: grab each real line from ssl.py
        def run_proc():
            while True:
                raw = self.process.stdout.readline()
                if not raw:
                    break
                try:
                    line = raw.decode('utf-8')
                except:
                    line = raw
                self._line_queue.put(line)
            self._line_queue.put(None)

        t = threading.Thread(target=run_proc)
        t.daemon = True
        t.start()

        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

    def _poll_log_queue(self):
        """Runs every 100ms on the GUI thread, flushes the queue into the Text widget."""
        try:
            while True:
                line = self._line_queue.get_nowait()
                if line is None:
                    self._on_end()
                else:
                    self._log(line)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_log_queue)

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
        """Insert a timestamped (HH:MM:SS) message into the log."""
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, "[%s] %s" % (ts, msg))
        self.log_text.see(tk.END)


if __name__ == '__main__':
    app = SSLStripUI()
    app.mainloop()
