from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout)

from hackingapp.models.attackTypeEnum import AttackType
from hackingapp.ui.toolbar.widget import ToolbarWidget
from hackingapp.ui.arp.interface import ARPInterface

class MainWindow(QMainWindow):
    """
    Main application window for the Scapy Attack Tool.
    Provides UI for ARP poisoning, DNS spoofing, SSL stripping, and PDF-based Help.
    """
    def __init__(self):
        super().__init__()

        # Setup window settings
        self.setWindowTitle("Scapy Attack Tool")
        self.resize(900, 600)

        # State flags and data
        self.current_attack = AttackType.ARP

        # Main layout
        central = QWidget()
        main_layout = QVBoxLayout(central)
        self.setCentralWidget(central)        

        # instantiate & install toolbar
        self.toolbar = ToolbarWidget(parent=self)
        self.addToolBar(self.toolbar)

        # Instantiate & install ARP interface
        self.arpInterface = ARPInterface(parent=self)
        main_layout.addLayout(self.arpInterface)

        # Hook toolbar iface event to ARP interface
        self.toolbar.ifaceSelectionUpdate.connect(self.arpInterface.onIfaceUpdate)
        self.arpInterface._iface = self.toolbar.interface_combo.currentText()

