from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit
)
import time
from .sslstrip_runner import SSLStripRunner

class SSLStripInterface(QVBoxLayout):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._iface = ""
        self._sslstrip = SSLStripRunner(self.log)
        self.running = False

        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.addWidget(QLabel("Logs:"))
        self.addWidget(self.log_edit)

        controls = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.pause_btn = QPushButton("Pause")
        self.stop_btn = QPushButton("Stop")
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)

        self.start_btn.clicked.connect(self.startTrigger)
        self.pause_btn.clicked.connect(self.pauseTrigger)
        self.stop_btn.clicked.connect(self.stopTrigger)

        controls.addWidget(self.start_btn)
        controls.addWidget(self.pause_btn)
        controls.addWidget(self.stop_btn)
        self.addLayout(controls)

    def onIfaceUpdate(self, iface: str):
        self._iface = iface
        self._sslstrip.setInterface(iface)
        self.log(f"Interface updated to {iface}")

    def startTrigger(self):
        if self.running:
            self.log("SSLStrip is already running.")
            return
        self._sslstrip.start()
        self.running = True
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)

    def pauseTrigger(self):
        self.log("Pause not supported in SSLStrip. You may stop and restart.")
    
    def stopTrigger(self):
        self._sslstrip.stop()
        self.running = False
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_edit.append(f"[{timestamp}] {message}")
