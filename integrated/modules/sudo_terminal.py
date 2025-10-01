import os
import shlex
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QFrame, QTextEdit, QLineEdit, QPushButton,
    QHBoxLayout, QLabel, QComboBox, QMessageBox, QInputDialog
)
from PyQt5.QtCore import QProcess, QSize, Qt
from PyQt5.QtGui import QFont, QIcon
from utils import db as command_db
from modules.dialogs import SudoCommandEditorDialog

class SudoTerminalWidget(QWidget):
    """A dedicated terminal for running commands with sudo."""
    def __init__(self, icon_path, parent=None):
        super().__init__(parent)
        self.icon_path = icon_path
        self.sudo_password = None
        self.process = QProcess(self)

        # --- Icons ---
        self.run_icon = QIcon(os.path.join(self.icon_path, "run.svg"))
        
        # --- Main Layout ---
        main_layout = QVBoxLayout(self)
        
        # --- Output Display ---
        self.output_display = QTextEdit(readOnly=True)
        self.output_display.setFont(QFont("Courier", 10))
        main_layout.addWidget(self.output_display)
        
        # --- Saved Commands ---
        saved_frame = QFrame()
        saved_frame.setFrameShape(QFrame.StyledPanel)
        saved_layout = QHBoxLayout(saved_frame)
        saved_layout.addWidget(QLabel("Run Saved Sudo Command:"))
        self.saved_commands_combo = QComboBox()
        saved_layout.addWidget(self.saved_commands_combo, 1)
        self.run_saved_btn = QPushButton("Run")
        self.run_saved_btn.setIcon(self.run_icon)
        saved_layout.addWidget(self.run_saved_btn)
        main_layout.addWidget(saved_frame)
        self.manage_btn = QPushButton("Manage")
        saved_layout.addWidget(self.manage_btn)

        # --- Custom Command ---
        custom_frame = QFrame()
        custom_frame.setFrameShape(QFrame.StyledPanel)
        custom_layout = QHBoxLayout(custom_frame)
        custom_layout.addWidget(QLabel("Run Custom Sudo Command:"))
        self.custom_command_input = QLineEdit()
        self.custom_command_input.setPlaceholderText("e.g., apt update")
        custom_layout.addWidget(self.custom_command_input, 1)
        self.run_custom_btn = QPushButton("Run")
        self.run_custom_btn.setIcon(self.run_icon)
        custom_layout.addWidget(self.run_custom_btn)
        main_layout.addWidget(custom_frame)

        # --- Connections ---
        self.run_saved_btn.clicked.connect(self.run_saved_command)
        self.run_custom_btn.clicked.connect(self.run_custom_command)
        self.custom_command_input.returnPressed.connect(self.run_custom_command)
        self.process.readyReadStandardOutput.connect(self.handle_output)
        self.process.finished.connect(self.handle_finish)
        self.manage_btn.clicked.connect(self.open_sudo_command_editor)
        self.load_saved_commands()

    def load_saved_commands(self):
        """Loads commands from the dedicated sudo_commands table."""
        self.saved_commands_combo.clear()
        commands = command_db.get_all_sudo_commands()
        if commands:
            self.saved_commands_combo.addItems([cmd['command_text'] for cmd in commands])
            self.saved_commands_combo.setEnabled(True)
        else:
            self.saved_commands_combo.addItem("No sudo commands found")
            self.saved_commands_combo.setEnabled(False)

    def open_sudo_command_editor(self):
        """Opens the dialog to manage sudo commands."""
        dialog = SudoCommandEditorDialog(self)
        dialog.exec_()
        self.load_saved_commands() # Reload commands after the dialog is closed
        
    def prompt_for_password(self):
        """Prompts for the sudo password if not already stored."""
        if self.sudo_password is None:
            text, ok = QInputDialog.getText(
                self, 'Sudo Password Required',
                'Please enter your password to run sudo commands:',
                QLineEdit.Password
            )
            if ok and text:
                self.sudo_password = text
                return True
            else:
                self.output_display.append("\n[ERROR] Sudo password not provided. Command aborted.")
                return False
        return True

    def run_saved_command(self):
        command = self.saved_commands_combo.currentText()
        if command and "No sudo commands found" not in command:
            self.execute_command(command)

    def run_custom_command(self):
        command = self.custom_command_input.text().strip()
        if command:
            # Prepend sudo if the user didn't type it
            if not command.startswith("sudo"):
                command = f"sudo {command}"
            self.execute_command(command)
            self.custom_command_input.clear()

    def execute_command(self, command):
        """Handles the logic of running a command with sudo."""
        if self.process.state() == QProcess.Running:
            QMessageBox.warning(self, "Process Busy", "A command is already running.")
            return

        if not self.prompt_for_password():
            return

        self.output_display.append(f"\n$ {command}")
        self.set_ui_running(True)

        # Use `sudo -S` to read the password from stdin
        command_parts = shlex.split(command)
        command_parts.insert(1, '-S')
        
        self.process.start(command_parts[0], command_parts[1:])
        if self.process.waitForStarted():
            self.process.write((self.sudo_password + '\n').encode())
        else:
            self.output_display.append(f"[ERROR] Failed to start process: {self.process.errorString()}")
            self.set_ui_running(False)

    def handle_output(self):
        self.output_display.append(self.process.readAllStandardOutput().data().decode(errors='ignore').strip())

    def handle_finish(self):
        exit_code = self.process.exitCode()
        self.output_display.append(f"\n--- Process finished with exit code: {exit_code} ---")
        self.set_ui_running(False)

    def set_ui_running(self, is_running):
        """Enables or disables UI elements based on process state."""
        self.run_saved_btn.setEnabled(not is_running)
        self.run_custom_btn.setEnabled(not is_running)
        self.custom_command_input.setEnabled(not is_running)
        self.saved_commands_combo.setEnabled(not is_running and self.saved_commands_combo.count() > 0 and "No sudo" not in self.saved_commands_combo.currentText())
