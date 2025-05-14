import sys
import threading
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QCheckBox, QTextEdit, QRadioButton, QButtonGroup, QToolBar
)
from PySide6.QtGui import QAction
# Import Scapy functions and protocols for network attacks
from scapy.all import ARP, Ether, send, sniff, DNS, DNSQR, DNSRR, IP, TCP, Raw

class MainWindow(QMainWindow):
    """
    Main application window for the Scapy Attack Tool.
    Provides UI elements to configure and launch ARP poisoning,
    DNS spoofing, and SSL stripping attacks.
    """
    def __init__(self):
        super().__init__()
        # Window setup: title and size
        self.setWindowTitle("Scapy Attack Tool")
        self.resize(800, 600)

        # Attributes for controlling attack thread
        self.attack_thread = None  # Thread running attack logic
        self.running = False       # Flag indicating if attack is active

        # ----------------------
        # Top toolbar components
        # ----------------------
        toolbar = QToolBar()
        self.addToolBar(toolbar)

        # Interface selection dropdown
        self.interface_combo = QComboBox()
        toolbar.addWidget(QLabel("Interface:"))
        toolbar.addWidget(self.interface_combo)

        # Spacer and actions: Load Profile, Help, Quit
        toolbar.addSeparator()
        load_action = QAction("Load Profile…", self)
        toolbar.addAction(load_action)
        help_action = QAction("Help", self)
        toolbar.addAction(help_action)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        toolbar.addAction(quit_action)

        # ----------------------
        # Central layout
        # ----------------------
        central = QWidget()
        main_layout = QVBoxLayout(central)
        self.setCentralWidget(central)

        # Horizontal split: Targets | Modes | Logs
        mid_layout = QHBoxLayout()
        main_layout.addLayout(mid_layout)

        # 1) Targets table: list of victim IPs and masks
        target_layout = QVBoxLayout()
        target_layout.addWidget(QLabel("Targets:"))
        self.target_table = QTableWidget(0, 2)
        self.target_table.setHorizontalHeaderLabels(["IP", "Mask"])
        target_layout.addWidget(self.target_table)
        add_row_btn = QPushButton("+ Add row")
        add_row_btn.clicked.connect(self.add_target_row)
        target_layout.addWidget(add_row_btn)
        mid_layout.addLayout(target_layout)

        # 2) Modes checkboxes: choose which attack(s) to run
        mode_layout = QVBoxLayout()
        mode_layout.addWidget(QLabel("Modes:"))
        self.arp_checkbox = QCheckBox("ARP Poisoning")
        self.dns_checkbox = QCheckBox("DNS Spoofing")
        self.ssl_checkbox = QCheckBox("SSL Stripping")
        mode_layout.addWidget(self.arp_checkbox)
        mode_layout.addWidget(self.dns_checkbox)
        mode_layout.addWidget(self.ssl_checkbox)
        mid_layout.addLayout(mode_layout)

        # 3) Logs text area: display runtime messages
        log_layout = QVBoxLayout()
        log_layout.addWidget(QLabel("Logs:"))
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        log_layout.addWidget(self.log_edit)
        mid_layout.addLayout(log_layout)

        # ----------------------
        # Bottom controls
        # ----------------------
        bottom_layout = QHBoxLayout()
        # Radio buttons for stealth vs. aggressive mode
        self.silent_radio = QRadioButton("Silent")
        self.allout_radio = QRadioButton("All-Out")
        radio_group = QButtonGroup(self)
        radio_group.addButton(self.silent_radio)
        radio_group.addButton(self.allout_radio)
        bottom_layout.addWidget(self.silent_radio)
        bottom_layout.addWidget(self.allout_radio)
        bottom_layout.addStretch()
        # Buttons to start, pause, and stop the attack
        self.start_btn = QPushButton("Start")
        self.pause_btn = QPushButton("Pause")
        self.stop_btn  = QPushButton("Stop")
        bottom_layout.addWidget(self.start_btn)
        bottom_layout.addWidget(self.pause_btn)
        bottom_layout.addWidget(self.stop_btn)
        main_layout.addLayout(bottom_layout)

        # Connect button signals to handler methods
        self.start_btn.clicked.connect(self.toggle_attack)
        self.pause_btn.clicked.connect(self.pause_attack)
        self.stop_btn.clicked.connect(self.stop_attack)

        # Populate network interfaces in the dropdown
        self.load_interfaces()

    def load_interfaces(self):
        """
        Populate the interface dropdown with available network interfaces.
        TODO: replace with dynamic detection (e.g., scapy.get_if_list()).
        """
        # Placeholder items
        self.interface_combo.addItems(['eth0', 'wlan0'])

    def add_target_row(self):
        """
        Append an empty row to the targets table for entering IP/mask.
        """
        row = self.target_table.rowCount()
        self.target_table.insertRow(row)
        # Create editable cells
        self.target_table.setItem(row, 0, QTableWidgetItem(""))
        self.target_table.setItem(row, 1, QTableWidgetItem(""))

    def get_targets(self):
        """
        Read all non-empty rows from the targets table.
        Returns:
            list of tuples: [(ip_str, mask_str), ...]
        """
        targets = []
        for row in range(self.target_table.rowCount()):
            ip_item = self.target_table.item(row, 0)
            mask_item = self.target_table.item(row, 1)
            if ip_item and ip_item.text():
                mask = mask_item.text() if mask_item else None
                targets.append((ip_item.text(), mask))
        return targets

    def toggle_attack(self):
        """
        Toggle attack state: start if not running, otherwise stop.
        """
        if not self.running:
            self.start_attack()
        else:
            self.stop_attack()

    def start_attack(self):
        """
        Begin the attack in a separate thread to avoid blocking the UI.
        Gathers all UI settings and launches run_attacks().
        """
        self.running = True
        self.log_edit.append("[+] Starting attack...")

        # Gather configuration from UI
        iface = self.interface_combo.currentText()
        targets = self.get_targets()
        arp = self.arp_checkbox.isChecked()
        dns = self.dns_checkbox.isChecked()
        ssl = self.ssl_checkbox.isChecked()
        mode = 'silent' if self.silent_radio.isChecked() else 'all-out'

        # Launch attack logic in background thread
        self.attack_thread = threading.Thread(
            target=self.run_attacks,
            args=(iface, targets, arp, dns, ssl, mode),
            daemon=True
        )
        self.attack_thread.start()

    def run_attacks(self, iface, targets, arp, dns, ssl, mode):
        """
        Perform the selected attacks based on parameters.
        This runs in a separate thread.
        """
        if arp:
            self.log_edit.append("[*] Launching ARP Poisoning")
            # TODO: Add ARP poisoning code
            # Example: send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, iface=iface), loop=True)
        if dns:
            self.log_edit.append("[*] Launching DNS Spoofing")
            # TODO: Sniff DNS queries and send spoofed responses
        if ssl:
            self.log_edit.append("[*] Launching SSL Stripping")
            # TODO: Intercept and modify HTTP->HTTPS redirects or use MitM proxy

        self.log_edit.append("[+] All selected attacks are running")

    def pause_attack(self):
        """
        Attempt to pause attack threads or loops.
        Note: pausing may require more complex thread control.
        """
        self.log_edit.append("[!] Pause not implemented")

    def stop_attack(self):
        """
        Signal the attack thread(s) to stop and perform cleanup.
        """
        self.running = False
        self.log_edit.append("[-] Stopping attack...")
        # TODO: Implement thread-safe shutdown of scapy loops

if __name__ == '__main__':
    # Standard PySide6 application bootstrap
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
