import os
import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QCheckBox, QTextEdit, QRadioButton, QButtonGroup, QToolBar, QLineEdit,
    QFileDialog, QMessageBox
)

def eventHelpButtonPressed(window):
    """
    Open a bundled PDF help file using the system default viewer.
    """
    # Assume help.pdf is in the same directory as this script
    app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    pdf_path = os.path.join(app_dir, 'help.pdf')
    if not os.path.exists(pdf_path):
        QMessageBox.critical(window, "Help File Missing", f"Could not find {pdf_path}")
        return
    QDesktopServices.openUrl(QUrl.fromLocalFile(pdf_path))

def eventAttackButtonPressed(window):
    if not window.running:
        window.start_attack()
    else:
        window.stop_attack()
    

def eventPauseButtonPressed(window):
        if not window.paused:
            window.paused = True
            window.pause_event.set()
            window.pause_btn.setText("Resume")
            window.log("[!] Paused")
        else:
            window.paused = False
            window.pause_event.clear()
            window.pause_btn.setText("Pause")
            window.log("[+] Resumed")