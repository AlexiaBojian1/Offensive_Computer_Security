from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout)

from hackingapp.models.attackTypeEnum import AttackType
from hackingapp.ui.toolbar.widget import ToolbarWidget
from hackingapp.ui.arp.interface import ARPInterface
from hackingapp.ui.dns.interface import DNSInterface
from hackingapp.ui.ssl.interface import SSLStripInterface

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
        self.arpWidget = QWidget()
        self.arpInterface = ARPInterface(parent=self.arpWidget)
        self.arpWidget.setLayout(self.arpInterface)
        main_layout.addWidget(self.arpWidget)

        # Instantiate & install DNS interface
        self.dnsWidget = QWidget()
        self.dnsInterface = DNSInterface(parent=self.dnsWidget)
        self.dnsWidget.setLayout(self.dnsInterface)
        main_layout.addWidget(self.dnsWidget)
        self.dnsWidget.setVisible(False)

        # Instantiate & install SSL interface
        self.sslWidget = QWidget()
        self.sslInterface = SSLStripInterface(parent=self.sslWidget)
        self.sslWidget.setLayout(self.sslInterface)
        main_layout.addWidget(self.sslWidget)
        self.sslWidget.setVisible(False)

        # Hook toolbar signals to interfaces
        self.toolbar.attackTypeChanged.connect(self.switch_attack_interface)
        self.toolbar.ifaceSelectionUpdate.connect(self.arpInterface.onIfaceUpdate)
        self.toolbar.dnsMappingLoaded.connect(self.dnsInterface.set_mapping)


        self.arpInterface._iface = self.toolbar.interface_combo.currentText()

    def switch_attack_interface(self, attack_type: str):
        self.arpWidget.setVisible(attack_type == "ARP")
        self.dnsWidget.setVisible(attack_type == "DNS")
        self.sslWidget.setVisible(attack_type == "SSL")