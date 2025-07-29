import sys
import os
import subprocess
import shlex
import threading
import argparse
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox,
    QDialog, QTableWidget, QTableWidgetItem, QSpinBox, QCheckBox,
    QDialogButtonBox, QAbstractItemView, QTabWidget, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QSize
from PyQt5.QtGui import QFont, QIcon

# Import the application's modules
import command_db
import recon_tools

class CommandEditorDialog(QDialog):
    """Dialog for managing commands in the database (CRUD operations)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage Commands")
        self.setGeometry(150, 150, 800, 500)
        self.setModal(True)
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Execution Order", "Command Text", "Use Shell"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setColumnHidden(0, True)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 500)
        layout.addWidget(self.table)
        button_layout = QHBoxLayout()
        add_btn, edit_btn, delete_btn = QPushButton("Add New"), QPushButton("Edit Selected"), QPushButton("Delete Selected")
        add_btn.clicked.connect(self.add_row)
        edit_btn.clicked.connect(self.edit_row)
        delete_btn.clicked.connect(self.delete_row)
        button_layout.addStretch()
        button_layout.addWidget(add_btn)
        button_layout.addWidget(edit_btn)
        button_layout.addWidget(delete_btn)
        layout.addLayout(button_layout)
        self.load_commands()

    def load_commands(self):
        self.table.setRowCount(0)
        for cmd in command_db.get_all_commands():
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(cmd['id'])))
            self.table.setItem(row, 1, QTableWidgetItem(str(cmd['execution_order'])))
            self.table.setItem(row, 2, QTableWidgetItem(cmd['command_text']))
            check_item = QTableWidgetItem()
            check_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            check_item.setCheckState(Qt.Checked if cmd['use_shell'] else Qt.Unchecked)
            self.table.setItem(row, 3, check_item)

    def add_row(self):
        dialog = CommandInputDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            command_db.add_command(data['text'], data['shell'], data['order'])
            self.load_commands()

    def edit_row(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected: return
        row = selected[0].row()
        cmd_id = int(self.table.item(row, 0).text())
        current_data = {'id': cmd_id, 'order': int(self.table.item(row, 1).text()), 'text': self.table.item(row, 2).text(), 'shell': self.table.item(row, 3).checkState() == Qt.Checked}
        dialog = CommandInputDialog(self, data=current_data)
        if dialog.exec_() == QDialog.Accepted:
            new_data = dialog.get_data()
            command_db.update_command(cmd_id, new_data['text'], new_data['shell'], new_data['order'])
            self.load_commands()

    def delete_row(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected: return
        row = selected[0].row()
        cmd_id = int(self.table.item(row, 0).text())
        if QMessageBox.question(self, "Confirm Deletion", "Are you sure you want to delete this command?") == QMessageBox.Yes:
            command_db.delete_command(cmd_id)
            self.load_commands()

class CommandInputDialog(QDialog):
    """Dialog for entering or editing a single command's details."""
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Command" if data else "Add Command")
        layout = QVBoxLayout(self)
        self.order_input = QSpinBox()
        self.order_input.setRange(1, 9999)
        self.order_input.setSingleStep(10)
        layout.addWidget(QLabel("Execution Order:"))
        layout.addWidget(self.order_input)
        self.text_input = QLineEdit()
        layout.addWidget(QLabel("Command Text (e.g., 'subfinder -d {target_name}' or 'internal:run_ipparser'):"))
        layout.addWidget(self.text_input)
        self.shell_check = QCheckBox("Requires Shell (for pipes, redirection, etc.)")
        layout.addWidget(self.shell_check)
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)
        if data:
            self.order_input.setValue(data['order'])
            self.text_input.setText(data['text'])
            self.shell_check.setChecked(data['shell'])

    def get_data(self):
        return {'order': self.order_input.value(), 'text': self.text_input.text().strip(), 'shell': self.shell_check.isChecked()}

class Worker(QThread):
    """Worker thread to run the reconnaissance commands."""
    progress = pyqtSignal(str)
    scan_updated = pyqtSignal()
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target_name, scope_file, working_directory):
        super().__init__()
        self.target_name = target_name
        self.scope_file = scope_file
        self.working_directory = working_directory
        self.is_running = True
        self.output_dir = os.path.join(self.working_directory, self.target_name)

    def stop(self):
        self.is_running = False
        self.progress.emit("--- Scan cancelled by user. ---")
        self.terminate()
        self.wait()

    def run_internal_command(self, command_text):
        self.progress.emit(f"[+] Running internal function: {command_text}")
        parts = shlex.split(command_text)
        func_name = parts[0].split(':')[1]
        parser = argparse.ArgumentParser()
        if func_name in ['run_domain_extracter', 'run_domain_enum', 'run_format_ips']:
             parser.add_argument('--input')
             parser.add_argument('--output')
             parser.add_argument('--subdomains')
             parser.add_argument('--scope')
        try:
            args, _ = parser.parse_known_args(parts[1:])
            args = vars(args)
            func_map = {
                'run_ipparser': (recon_tools.run_ipparser, {'scope_file_path': self.scope_file, 'output_dir': self.output_dir}),
                'run_domain_extracter': (recon_tools.run_domain_extracter, {'input_file_path': os.path.join(self.output_dir, args['input']), 'output_file_path': os.path.join(self.output_dir, args['output'])}),
                'run_domain_enum': (recon_tools.run_domain_enum, {'subdomains_file_path': os.path.join(self.output_dir, args['subdomains']), 'scope_file_path': os.path.join(self.output_dir, args['scope']), 'output_file_path': os.path.join(self.output_dir, args['output'])}),
                'run_format_ips': (recon_tools.run_format_ips, {'input_file_path': os.path.join(self.output_dir, args['input'])})
            }
            if func_name in func_map:
                func, f_args = func_map[func_name]
                success, message = func(**f_args)
                if success:
                    self.progress.emit(f"[✔] {message}")
                    return True, message if func_name == 'run_format_ips' else None
                else:
                    self.error.emit(message)
                    return False, None
            else:
                self.error.emit(f"Unknown internal function: {func_name}")
                return False, None
        except Exception as e:
            self.error.emit(f"Error running internal function {func_name}: {e}")
            return False, None

    def run_external_command(self, command_text, use_shell, pipe_input=None):
        self.progress.emit(f"[+] Running: {command_text}")
        try:
            process_args = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'text': True, 'cwd': self.output_dir}
            if pipe_input: process_args['stdin'] = subprocess.PIPE
            if use_shell:
                process_args['shell'] = True
                process = subprocess.Popen(command_text, **process_args)
            else:
                process_args['shell'] = False
                process = subprocess.Popen(shlex.split(command_text), **process_args)
            if pipe_input:
                process.stdin.write(pipe_input)
                process.stdin.close()
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    if not self.is_running: process.terminate(); break
                    self.progress.emit(line.strip())
                process.stdout.close()
            return_code = process.wait()
            stderr_output = process.stderr.read()
            if stderr_output: self.progress.emit(f"[!] Stderr: {stderr_output.strip()}")
            if return_code != 0:
                self.progress.emit(f"[!] Command failed: {command_text}")
                return False
            self.progress.emit(f"[✔] Finished: {command_text}")
            return True
        except Exception as e:
            self.error.emit(f"Failed to execute command '{command_text}': {e}")
            return False

    def run(self):
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)
        commands = command_db.get_all_commands()
        if not commands:
            self.error.emit("No commands found in the database."); self.finished.emit(); return
        for cmd in commands:
            if not self.is_running: break
            command_text, use_shell = cmd['command_text'], cmd['use_shell']
            
            success = False
            if '|' in command_text and use_shell:
                parts = command_text.split('|', 1)
                first_cmd, second_cmd = parts[0].strip(), parts[1].strip()
                if first_cmd.startswith('internal:'):
                    succ, pipe_input = self.run_internal_command(first_cmd)
                    if succ:
                        success = self.run_external_command(second_cmd, use_shell, pipe_input=pipe_input)
                else:
                    success = self.run_external_command(command_text, use_shell)
            elif command_text.startswith('internal:'):
                success, _ = self.run_internal_command(command_text)
            else:
                success = self.run_external_command(command_text, use_shell)

            if success:
                self.scan_updated.emit()
            else:
                self.error.emit("Stopping scan due to command failure.")
                break

        if self.is_running: self.progress.emit("\n[***] Reconnaissance Scan Completed [***]")
        self.finished.emit()

class ReconAutomatorApp(QMainWindow):
    """Main application window."""
    def __init__(self, working_directory):
        super().__init__()
        self.setWindowTitle("Reconnaissance Automator")
        self.setGeometry(100, 100, 900, 700)
        self.working_directory = working_directory
        self.worker = None
        
        self.create_icons()

        # --- Main Layout with Tabs ---
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # --- Tab 1: Scan Control ---
        scan_control_widget = QWidget()
        self.tabs.addTab(scan_control_widget, "Scan Control")
        main_layout = QVBoxLayout(scan_control_widget)

        top_bar_layout = QHBoxLayout()
        top_bar_layout.addStretch()
        self.theme_button = QPushButton()
        self.theme_button.setFlat(True)
        self.theme_button.setIconSize(QSize(24, 24))
        self.theme_button.clicked.connect(self.toggle_theme)
        top_bar_layout.addWidget(self.theme_button)
        main_layout.addLayout(top_bar_layout)

        input_layout = QHBoxLayout()
        self.target_name_entry = QLineEdit()
        self.scope_file_label = QLabel("No file selected")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_scope_file)
        input_layout.addWidget(QLabel("Target Name:"))
        input_layout.addWidget(self.target_name_entry)
        input_layout.addWidget(QLabel("Scope File:"))
        input_layout.addWidget(self.scope_file_label, 1)
        input_layout.addWidget(browse_button)
        main_layout.addLayout(input_layout)

        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.setObjectName("StartButton")
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan", enabled=False)
        self.stop_button.setObjectName("StopButton")
        self.stop_button.clicked.connect(self.stop_scan)
        self.manage_button = QPushButton("Manage Commands")
        self.manage_button.clicked.connect(self.open_command_editor)
        button_layout.addWidget(self.manage_button)
        button_layout.addStretch()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        main_layout.addLayout(button_layout)

        self.output_log = QTextEdit(readOnly=True)
        self.output_log.setFont(QFont("Courier", 10))
        main_layout.addWidget(self.output_log)

        # --- Tab 2: Output Files ---
        output_files_widget = QWidget()
        self.tabs.addTab(output_files_widget, "Output Files")
        output_layout = QVBoxLayout(output_files_widget)
        self.output_files_list = QListWidget()
        output_layout.addWidget(self.output_files_list)

        self.apply_theme()

    def create_icons(self):
        """Creates QIcon objects from SVG data."""
        sun_svg = b'<svg ...> ... </svg>' # (Content omitted for brevity)
        moon_svg = b'<svg ...> ... </svg>' # (Content omitted for brevity)
        file_svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>'
        
        self.sun_icon = QIcon(str(sun_svg))
        self.moon_icon = QIcon(str(moon_svg))
        self.file_icon = QIcon(str(file_svg))

    def apply_theme(self):
        theme_name = command_db.get_setting('active_theme')
        stylesheet = command_db.get_setting(f"{theme_name}_theme_stylesheet")
        self.setStyleSheet(stylesheet)
        if theme_name == 'dark':
            self.theme_button.setIcon(self.sun_icon)
            self.theme_button.setToolTip("Switch to Light Mode")
        else:
            self.theme_button.setIcon(self.moon_icon)
            self.theme_button.setToolTip("Switch to Dark Mode")

    def toggle_theme(self):
        current_theme = command_db.get_setting('active_theme')
        new_theme = 'light' if current_theme == 'dark' else 'dark'
        command_db.update_setting('active_theme', new_theme)
        self.apply_theme()

    def open_command_editor(self):
        CommandEditorDialog(self).exec_()

    def browse_scope_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Scope File", self.working_directory)
        if file_path:
            self.scope_file_path = file_path
            self.scope_file_label.setText(os.path.basename(file_path))

    def refresh_output_files(self):
        """Clears and repopulates the output files list."""
        self.output_files_list.clear()
        target_name = self.target_name_entry.text().strip()
        if not target_name:
            return

        output_dir = os.path.join(self.working_directory, target_name)
        if not os.path.isdir(output_dir):
            return
            
        try:
            for filename in sorted(os.listdir(output_dir)):
                item = QListWidgetItem(self.file_icon, filename)
                self.output_files_list.addItem(item)
        except OSError as e:
            self.show_error_message(f"Could not read output directory: {e}")

    def start_scan(self):
        target_name = self.target_name_entry.text().strip()
        scope_file = getattr(self, 'scope_file_path', None)
        if not target_name or not scope_file:
            QMessageBox.warning(self, "Input Error", "Please provide a target name and select a scope file.")
            return

        self.output_log.clear()
        self.output_files_list.clear()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.manage_button.setEnabled(False)

        self.worker = Worker(target_name=target_name, scope_file=scope_file, working_directory=self.working_directory)
        self.worker.progress.connect(self.update_log)
        self.worker.scan_updated.connect(self.refresh_output_files)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(self.show_error_message)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()

    def update_log(self, message):
        self.output_log.append(message)

    def scan_finished(self):
        self.refresh_output_files() # Final refresh
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.manage_button.setEnabled(True)
        self.worker = None

    def show_error_message(self, message):
        self.update_log(f"[!!!] ERROR: {message}")
        QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    command_db.initialize_db() 

    # Prompt for working directory before starting the app
    working_dir = QFileDialog.getExistingDirectory(None, "Select a Working Directory", os.path.expanduser("~"))
    
    if working_dir:
        main_win = ReconAutomatorApp(working_directory=working_dir)
        main_win.show()
        sys.exit(app.exec_())
    else:
        # If user cancels the directory selection, exit the application
        sys.exit(0)
