import sys
import os

from PySide6.QtWidgets import (
    QLabel, QComboBox, QToolBar, QLineEdit, QFileDialog, QMessageBox
)
from PySide6.QtCore import (QUrl, Signal)
from PySide6.QtGui import QDesktopServices
from PySide6.QtGui import QAction
from scapy.all import get_if_list

class ToolbarWidget(QToolBar):

    ifaceSelectionUpdate = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        # Toolbar setup
        self.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.addWidget(self.interface_combo)
        self.addSeparator()
        # Forward iface selection update
        self.interface_combo.currentTextChanged.connect(self.ifaceSelectionUpdate)

        self.addWidget(QLabel("Attack:"))
        self.attack_combo = QComboBox()
        self.addWidget(self.attack_combo)
        self.addSeparator()

        dns_map_action = QAction("Load DNS Mapping…", self)
        dns_map_action.triggered.connect(self.dnsSpoofSelectTrigger)
        self.addAction(dns_map_action)

        self.mapping_path = QLineEdit(self)
        self.mapping_path.setReadOnly(True)
        self.mapping_path.setPlaceholderText("No DNS mapping loaded")
        self.addWidget(self.mapping_path)
        self.addSeparator()

        help_action = QAction("Help", self)
        help_action.triggered.connect(self.helpButtonTrigger)
        self.addAction(help_action)
        self.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        self.addAction(quit_action)

        # Load interfaces
        self.load_interfaces()
        self.load_attacks()
        self.load_attack_interface()

    def dnsSpoofSelectTrigger(self):
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

    def helpButtonTrigger(self):
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
        try:
            interfaces = get_if_list()
        except Exception as e:
            print(f"Error loading interfaces: {e}")
            interfaces = ["eth0", "wlan0"]  # Fallback if Scapy fails
        
        self.interface_combo.clear()
        self.interface_combo.addItems(interfaces)

    def load_attacks(self):
        self.attack_combo.addItems(["ARP", "DNS", "SSL"])

    def load_attack_interface(self):
        return