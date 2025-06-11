import time
from pathlib import Path

from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit,
    QCheckBox, QHeaderView
)

from ...logic.dns import DNSSpoofer


class DNSInterface(QVBoxLayout):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.running = False
        self.paused = False
        self._iface = ""
        self._dnsSpoofer = None
        self._mapping = {}

        # Layout containers
        horizontalContainer = QHBoxLayout()
        self.addLayout(horizontalContainer)
        
        # Logs
        log_layout = QVBoxLayout()
        log_layout.addWidget(QLabel("Logs:"))
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        log_layout.addWidget(self.log_edit)
        horizontalContainer.addLayout(log_layout, 3)

        # Controls
        bottom_layout = QHBoxLayout()
        self.relay_checkbox = QCheckBox("Relay unmatched queries")
        bottom_layout.addWidget(self.relay_checkbox)
        bottom_layout.addStretch()
        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.startButtonTrigger)
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.clicked.connect(self.pauseButtonTrigger)
        self.pause_btn.setEnabled(False)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stopButtonTrigger)
        self.stop_btn.setEnabled(False)
        bottom_layout.addWidget(self.start_btn)
        bottom_layout.addWidget(self.pause_btn)
        bottom_layout.addWidget(self.stop_btn)
        self.addLayout(bottom_layout)

    def onIfaceUpdate(self, text: str):
        self._iface = text
        self.log(f"Interface changed: {self._iface}")

    def addRowTrigger(self):
        row = self.map_table.rowCount()
        self.map_table.insertRow(row)
        for col in range(2):
            self.map_table.setItem(row, col, QTableWidgetItem(""))

    def set_mapping(self, mapping: dict):
        self._mapping = mapping
        self.log("[+] DNS mapping loaded with {len(self.dns_mapping)} entries.")

    def startButtonTrigger(self):
        if self.running:
            self.log("Already running.")
            return

        if not self._mapping:
            self.log("[!] No DNS mappings provided.")
            return

        self.running = True
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)

        self._dnsSpoofer = DNSSpoofer(
            iface=self._iface,
            mapping=self._mapping,
            log=self.log,
            relay=self.relay_checkbox.isChecked()
        )
        self._dnsSpoofer.start()
        self.log("[+] DNS spoofing started.")

    def pauseButtonTrigger(self):
        self.log("[!] Pause not supported for DNS spoofing.")

    def stopButtonTrigger(self):
        if not self.running:
            self.log("Not running.")
            return

        self.running = False
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)

        if self._dnsSpoofer:
            self._dnsSpoofer.stop()
            self._dnsSpoofer = None
        self.log("[-] DNS spoofing stopped.")

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_edit.append(f"[{timestamp}] {message}")
