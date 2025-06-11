import time


from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QTableWidget, QTableWidgetItem, QTextEdit, 
    QRadioButton, QButtonGroup, QHeaderView
)

from hackingapp.logic.arp_poisoning import ARPPoisoner

class ARPInterface(QVBoxLayout):

    def __init__(self, parent=None):
        super().__init__(parent)

        # State flags and data
        self.running = False
        self.paused = False
        self._iface = ""
        self._arpPoisoner = ARPPoisoner(self.log)
        

        # Container for the IP rows + Logs
        horizontalContainer = QHBoxLayout()
        self.addLayout(horizontalContainer)

        # Targets table for ARP spoofing
        target_layout = QVBoxLayout()
        target_layout.addWidget(QLabel("IP (Target / Spoof):"))
        self.target_table = QTableWidget(0, 2)
        self.target_table.setHorizontalHeaderLabels(["Target", "Spoof"])
        # Make the columns stretch the width
        self.target_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        target_layout.addWidget(self.target_table)
        add_row_btn = QPushButton("+ Add row")
        add_row_btn.clicked.connect(self.addRowTrigger)
        target_layout.addWidget(add_row_btn)
        horizontalContainer.addLayout(target_layout, 3)

        # Logs view
        log_layout = QVBoxLayout()
        log_layout.addWidget(QLabel("Logs:"))
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        log_layout.addWidget(self.log_edit)
        horizontalContainer.addLayout(log_layout, 3)

        # Bottom controls
        bottom_layout = QHBoxLayout()
        self.silent_radio = QRadioButton("Silent")
        self.allout_radio = QRadioButton("All-Out")
        radio_group = QButtonGroup(self)
        radio_group.addButton(self.silent_radio)
        radio_group.addButton(self.allout_radio)
        bottom_layout.addWidget(self.silent_radio)
        bottom_layout.addWidget(self.allout_radio)
        bottom_layout.addStretch()
        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.startkButtonTrigger)
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
        """Update Network interface for the ARP attack"""
        self._iface = text
        self.log("Inteface changed: {self._iface}")
        self._arpPoisoner.setInterface(self._iface)

    def addRowTrigger(self):
        """Add a new empty row to the targets table"""
        row = self.target_table.rowCount()
        self.target_table.insertRow(row)
        for col in range(2):
            self.target_table.setItem(row, col, QTableWidgetItem(""))

    def startkButtonTrigger(self):
        """Start the ARP poisoning attack"""
        if self.running:
            self.log("Cannot start attack as it is already running.")
            return
    
        self.running = True
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.log("[+] Starting ARP poisoning...")
        targets = self.get_targets()
        # Launch poisoning thread
        self._arpPoisoner.setInterface(self._iface)
        self._arpPoisoner.setTargets(targets)
        self._arpPoisoner.start()
        

    def pauseButtonTrigger(self):
        """Pause the ARP poisoning attack"""
        if not self.running:
            self.log("Cannot stop attack as it is not running.")
            return
        if not self.paused:
            self.paused = True
            self.pause_btn.setText("Resume")
            self._arpPoisoner.pause()
            self.log("[!] Paused")
        else:
            self.paused = False
            self.pause_btn.setText("Pause")
            self._arpPoisoner.pause()
            self.log("[+] Resumed")
    
    def stopButtonTrigger(self):
        """Stop the ARP poisoning attack"""
        if not self.running:
            self.log("Cannot stop attack as it has not started yet.")
            return
        
        self.running = False
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self._arpPoisoner.stop()
        self.log("[-] Stopped")

    def get_targets(self):
        """"Read table entries and return list of (target_ip, gateway_ip)"""
        targets = []
        for row in range(self.target_table.rowCount()):
            target_item = self.target_table.item(row, 0)
            gateway_item = self.target_table.item(row, 1)
            if target_item and gateway_item:
                target = target_item.text().strip()
                gateway = gateway_item.text().strip()
                if (target and gateway):
                    targets.append((target, gateway))
        return targets

    def log(self, message):
        """Append a timestamped message to the log view."""
        timestamp = time.strftime("%H:%M:%S")
        self.log_edit.append(f"[{timestamp}] {message}")