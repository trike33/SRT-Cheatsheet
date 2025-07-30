import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget
from PyQt5.QtCore import QSize
from PyQt5.QtGui import QIcon

# Import utility and module classes
from utils import db as command_db
from modules.scan_control import ScanControlWidget
from modules.playground import PlaygroundTabWidget
from modules.custom_commands import CustomCommandsWidget

class ReconAutomatorApp(QMainWindow):
    """
    The main application window that acts as an orchestrator for all the modular components (tabs).
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Reconnaissance Automator")
        self.setGeometry(100, 100, 1200, 800)
        
        self.working_directory = os.path.expanduser("~")
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.icon_path = os.path.join(self.base_path, "resources", "img")

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # --- Instantiate Modular Widgets ---
        self.scan_control_tab = ScanControlWidget(self.working_directory, self.icon_path)
        self.playground_tab = PlaygroundTabWidget(self.working_directory, self.icon_path)
        self.terminal_tab = CustomCommandsWidget(self.working_directory, self.icon_path)


        # --- Add Widgets as Tabs ---
        self.tabs.addTab(self.scan_control_tab, "Scan Control")
        self.tabs.addTab(self.playground_tab, "Playground")
        self.tabs.addTab(self.terminal_tab, "Terminal")


        # --- Connect Signals Between Modules ---
        self.scan_control_tab.scan_updated.connect(self.playground_tab.refresh_playground)
        self.scan_control_tab.cwd_changed.connect(self.on_cwd_changed)
        self.scan_control_tab.theme_changed.connect(self.apply_theme)
        
        self.apply_theme()

    def on_cwd_changed(self, new_path):
        """Broadcasts the CWD change to all interested modules."""
        self.working_directory = new_path
        self.playground_tab.set_working_directory(new_path)
        self.terminal_tab.set_working_directory(new_path)

    def apply_theme(self):
        """Applies the current theme and reloads icons for all modules."""
        theme_name = command_db.get_setting('active_theme')
        stylesheet = command_db.get_setting(f"{theme_name}_theme_stylesheet")
        self.setStyleSheet(stylesheet)
        self.scan_control_tab.apply_theme(theme_name)
        self.playground_tab.apply_theme()

    def closeEvent(self, event):
        """Ensures all child processes are terminated when the app closes."""
        self.terminal_tab.stop_all_processes()
        if self.scan_control_tab.worker and self.scan_control_tab.worker.isRunning():
            self.scan_control_tab.worker.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    command_db.initialize_db()
    main_win = ReconAutomatorApp()
    main_win.show()
    sys.exit(app.exec_())