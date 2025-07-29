import sys
import os
import subprocess
import shlex
import threading
import argparse
import time
import re
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox,
    QDialog, QTableWidget, QTableWidgetItem, QSpinBox, QCheckBox,
    QDialogButtonBox, QAbstractItemView, QTabWidget, QListWidget, QListWidgetItem,
    QProgressBar
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QSize, QTimer
from PyQt5.QtGui import QFont, QIcon, QPixmap

# Import the application's modules
import command_db
import recon_tools

class DomainsFileDialog(QDialog):
    """A dialog to create, edit, and save a domains file before the main app starts."""
    def __init__(self, working_directory, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.domains_file_path = ""
        self.setWindowTitle("Setup Domains File")
        self.setMinimumSize(500, 400)

        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Enter domains (one per line) or open an existing file."))
        
        self.text_editor = QTextEdit()
        layout.addWidget(self.text_editor)

        button_layout = QHBoxLayout()
        browse_button = QPushButton("Open Existing File")
        browse_button.clicked.connect(self.browse_file)
        button_layout.addWidget(browse_button)
        button_layout.addStretch()
        
        self.button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.button_box.button(QDialogButtonBox.Save).setText("Save and Continue")
        self.button_box.accepted.connect(self.save_and_accept)
        self.button_box.rejected.connect(self.reject)
        button_layout.addWidget(self.button_box)

        layout.addLayout(button_layout)

    def browse_file(self):
        """Opens a file dialog to select an existing domains file."""
        path, _ = QFileDialog.getOpenFileName(self, "Open Domains File", self.working_directory, "Text Files (*.txt);;All Files (*)")
        if path:
            self.domains_file_path = path
            try:
                with open(path, 'r') as f:
                    self.text_editor.setText(f.read())
                self.setWindowTitle(f"Editing: {os.path.basename(path)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not read file: {e}")

    def save_and_accept(self):
        """Saves the content to a new or existing file and closes the dialog."""
        if not self.domains_file_path:
            path, _ = QFileDialog.getSaveFileName(self, "Save Domains File As", os.path.join(self.working_directory, "domains.txt"), "Text Files (*.txt);;All Files (*)")
            if not path:
                return # User cancelled save dialog
            self.domains_file_path = path
        
        try:
            with open(self.domains_file_path, 'w') as f:
                f.write(self.text_editor.toPlainText())
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not save file: {e}")

class CommandEditorDialog(QDialog):
    """Dialog for managing commands in the database (CRUD operations)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage Commands")
        self.setGeometry(150, 150, 800, 500)
        self.setModal(True)
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Execution Order", "Command Text", "Use Shell", "Background"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setColumnHidden(0, True)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 450)
        self.table.setColumnWidth(3, 80)
        self.table.setColumnWidth(4, 80)
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
            
            shell_check = QTableWidgetItem()
            shell_check.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            shell_check.setCheckState(Qt.Checked if cmd['use_shell'] else Qt.Unchecked)
            self.table.setItem(row, 3, shell_check)

            bg_check = QTableWidgetItem()
            bg_check.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            bg_check.setCheckState(Qt.Checked if cmd['run_in_background'] else Qt.Unchecked)
            self.table.setItem(row, 4, bg_check)

    def add_row(self):
        dialog = CommandInputDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            command_db.add_command(data['text'], data['shell'], data['order'], data['background'])
            self.load_commands()

    def edit_row(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected: return
        row = selected[0].row()
        cmd_id = int(self.table.item(row, 0).text())
        current_data = {
            'id': cmd_id, 
            'order': int(self.table.item(row, 1).text()), 
            'text': self.table.item(row, 2).text(), 
            'shell': self.table.item(row, 3).checkState() == Qt.Checked,
            'background': self.table.item(row, 4).checkState() == Qt.Checked
        }
        dialog = CommandInputDialog(self, data=current_data)
        if dialog.exec_() == QDialog.Accepted:
            new_data = dialog.get_data()
            command_db.update_command(cmd_id, new_data['text'], new_data['shell'], new_data['order'], new_data['background'])
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
        
        checkbox_layout = QHBoxLayout()
        self.shell_check = QCheckBox("Requires Shell (for pipes, etc.)")
        self.background_check = QCheckBox("Run in Background")
        checkbox_layout.addWidget(self.shell_check)
        checkbox_layout.addWidget(self.background_check)
        layout.addLayout(checkbox_layout)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)
        if data:
            self.order_input.setValue(data['order'])
            self.text_input.setText(data['text'])
            self.shell_check.setChecked(data['shell'])
            self.background_check.setChecked(data['background'])

    def get_data(self):
        return {
            'order': self.order_input.value(), 
            'text': self.text_input.text().strip(), 
            'shell': self.shell_check.isChecked(),
            'background': self.background_check.isChecked()
        }

class Worker(QThread):
    """Worker thread to run the reconnaissance commands."""
    progress = pyqtSignal(str)
    progress_updated = pyqtSignal(int, int)
    scan_updated = pyqtSignal()
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target_name, scope_file, working_directory, total_commands):
        super().__init__()
        self.target_name = target_name
        self.scope_file = scope_file
        self.working_directory = working_directory
        self.total_commands = total_commands
        self.is_running = True
        self.output_dir = os.path.join(self.working_directory, self.target_name)
        self.background_processes = []

    def stop(self):
        self.is_running = False
        self.progress.emit("--- Scan cancelled by user. ---")
        for proc in self.background_processes:
            try:
                proc.terminate()
            except Exception as e:
                self.progress.emit(f"[!] Could not terminate background process {proc.pid}: {e}")
        self.terminate()
        self.wait()

    def run_background_command(self, command_text, use_shell):
        """Launches a command as a non-blocking background process."""
        self.progress.emit(f"[+] Starting background command: {command_text}")
        try:
            process_args = {
                'stdout': subprocess.DEVNULL,
                'stderr': subprocess.DEVNULL,
                'cwd': self.output_dir
            }
            if use_shell:
                process_args['shell'] = True
                proc = subprocess.Popen(command_text, **process_args)
            else:
                process_args['shell'] = False
                proc = subprocess.Popen(shlex.split(command_text), **process_args)
            
            self.background_processes.append(proc)
            return True
        except Exception as e:
            self.error.emit(f"Failed to start background command '{command_text}': {e}")
            return False

    def run_internal_command(self, command_text):
        self.progress.emit(f"[+] Running internal function: {command_text}")
        parts = shlex.split(command_text)
        func_name = parts[0].split(':')[1]
        try:
            if func_name == 'run_ipparser':
                success, message = recon_tools.run_ipparser(scope_file_path=self.scope_file, output_dir=self.output_dir)
                if success: self.progress.emit(f"[✔] {message}")
                return success, None
            parser = argparse.ArgumentParser(description=f'Parser for {func_name}')
            if func_name == 'run_domain_extracter':
                parser.add_argument('--input', required=True); parser.add_argument('--output', required=True)
                args = parser.parse_args(parts[1:])
                success, message = recon_tools.run_domain_extracter(input_file_path=os.path.join(self.output_dir, args.input), output_file_path=os.path.join(self.output_dir, args.output))
                if success: self.progress.emit(f"[✔] {message}")
                return success, None
            elif func_name == 'run_domain_enum':
                parser.add_argument('--subdomains', required=True); parser.add_argument('--scope', required=True); parser.add_argument('--output', required=True)
                args = parser.parse_args(parts[1:])
                success, message = recon_tools.run_domain_enum(subdomains_file_path=os.path.join(self.output_dir, args.subdomains), scope_file_path=os.path.join(self.output_dir, args.scope), output_file_path=os.path.join(self.output_dir, args.output))
                if success: self.progress.emit(f"[✔] {message}")
                return success, None
            elif func_name == 'run_format_ips':
                parser.add_argument('--input', required=True)
                args = parser.parse_args(parts[1:])
                success, message = recon_tools.run_format_ips(input_file_path=os.path.join(self.output_dir, args.input))
                if success: self.progress.emit(f"[✔] IP Formatter prepared data for piping.")
                return success, message
            else:
                self.error.emit(f"Unknown internal function: {func_name}"); return False, None
        except Exception as e:
            self.error.emit(f"Error processing internal function '{func_name}': {e}"); return False, None

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
                self.progress.emit(f"[!] Command failed: {command_text}"); return False
            self.progress.emit(f"[✔] Finished: {command_text}"); return True
        except Exception as e:
            self.error.emit(f"Failed to execute command '{command_text}': {e}"); return False

    def run(self):
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)
        commands = command_db.get_all_commands()
        if not commands:
            self.error.emit("No commands found in the database."); self.finished.emit(); return
        
        for i, cmd in enumerate(commands):
            if not self.is_running: break
            command_text, use_shell, run_in_bg = cmd['command_text'], cmd['use_shell'], cmd['run_in_background']
            
            success = False
            if run_in_bg:
                success = self.run_background_command(command_text, use_shell)
            elif '|' in command_text and use_shell:
                parts = command_text.split('|', 1)
                first_cmd, second_cmd = parts[0].strip(), parts[1].strip()
                if first_cmd.startswith('internal:'):
                    succ, pipe_input = self.run_internal_command(first_cmd)
                    if succ: success = self.run_external_command(second_cmd, use_shell, pipe_input=pipe_input)
                else:
                    success = self.run_external_command(command_text, use_shell)
            elif command_text.startswith('internal:'):
                success, _ = self.run_internal_command(command_text)
            else:
                success = self.run_external_command(command_text, use_shell)

            if success:
                self.scan_updated.emit()
                self.progress_updated.emit(i + 1, self.total_commands)
            else:
                self.error.emit("Stopping scan due to command failure."); break

        if self.is_running: self.progress.emit("\n[***] Main scan sequence completed. Background tasks may still be running. [***]")
        self.finished.emit()

class ReconAutomatorApp(QMainWindow):
    """Main application window."""
    def __init__(self, working_directory, domains_file):
        super().__init__()
        self.setWindowTitle("Reconnaissance Automator")
        self.setGeometry(100, 100, 900, 700)
        self.working_directory = working_directory
        self.domains_file_path = domains_file
        self.worker = None
        self.create_icons()
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
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
        browse_button = QPushButton("Browse Scope File")
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
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.timer_label = QLabel("Elapsed Time: 00:00:00")
        self.timer_label.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.timer_label)
        main_layout.addLayout(progress_layout)
        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self.update_timer_display)
        self.elapsed_time = 0
        self.output_log = QTextEdit(readOnly=True)
        self.output_log.setFont(QFont("Courier", 10))
        main_layout.addWidget(self.output_log)
        output_files_widget = QWidget()
        self.tabs.addTab(output_files_widget, "Output Files")
        output_layout = QVBoxLayout(output_files_widget)
        self.output_files_list = QListWidget()
        output_layout.addWidget(self.output_files_list)
        self.apply_theme()

    def create_icons(self):
        """Creates QIcon objects from SVG data using QPixmap."""
        sun_svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>'
        moon_svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>'
        file_svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>'
        
        sun_pixmap = QPixmap()
        sun_pixmap.loadFromData(sun_svg)
        self.sun_icon = QIcon(sun_pixmap)

        moon_pixmap = QPixmap()
        moon_pixmap.loadFromData(moon_svg)
        self.moon_icon = QIcon(moon_pixmap)

        file_pixmap = QPixmap()
        file_pixmap.loadFromData(file_svg)
        self.file_icon = QIcon(file_pixmap)

    def ansi_to_html(self, text):
        """Converts text with ANSI color codes to HTML."""
        color_map = {
            '30': 'black', '31': 'red', '32': 'green', '33': 'yellow',
            '34': 'blue', '35': 'magenta', '36': 'cyan', '37': 'white',
            '90': 'grey', '91': 'lightcoral', '92': 'lightgreen', '93': 'lightyellow',
            '94': 'lightblue', '95': 'lightpink', '96': 'lightcyan'
        }
        def replace_color(match):
            code = match.group(1)
            color = color_map.get(code, 'white')
            return f'<span style="color:{color}">'
        html = re.sub(r'\x1b\[(\d+)m', replace_color, text)
        html = html.replace('\x1b[0m', '</span>')
        if html.count('<span') > html.count('</span>'):
            html += '</span>' * (html.count('<span') - html.count('</span>'))
        return html.replace('\n', '<br>')

    def apply_theme(self):
        theme_name = command_db.get_setting('active_theme')
        stylesheet = command_db.get_setting(f"{theme_name}_theme_stylesheet")
        self.setStyleSheet(stylesheet)
        if theme_name == 'dark':
            self.theme_button.setIcon(self.sun_icon); self.theme_button.setToolTip("Switch to Light Mode")
        else:
            self.theme_button.setIcon(self.moon_icon); self.theme_button.setToolTip("Switch to Dark Mode")

    def toggle_theme(self):
        current_theme = command_db.get_setting('active_theme')
        new_theme = 'light' if current_theme == 'dark' else 'dark'
        command_db.update_setting('active_theme', new_theme)
        self.apply_theme()

    def open_command_editor(self): CommandEditorDialog(self).exec_()
    def browse_scope_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Scope File", self.working_directory)
        if file_path: self.scope_file_path = file_path; self.scope_file_label.setText(os.path.basename(file_path))

    def refresh_output_files(self):
        self.output_files_list.clear()
        target_name = self.target_name_entry.text().strip()
        if not target_name: return
        output_dir = os.path.join(self.working_directory, target_name)
        if not os.path.isdir(output_dir): return
        try:
            for filename in sorted(os.listdir(output_dir)): self.output_files_list.addItem(QListWidgetItem(self.file_icon, filename))
        except OSError as e: self.show_error_message(f"Could not read output directory: {e}")

    def update_progress_bar(self, current_step, total_steps):
        self.progress_bar.setValue(current_step); self.progress_bar.setFormat(f"Step {current_step}/{total_steps}")
    
    def update_timer_display(self):
        self.elapsed_time += 1; hours = self.elapsed_time // 3600; minutes = (self.elapsed_time % 3600) // 60; seconds = self.elapsed_time % 60
        self.timer_label.setText(f"Elapsed Time: {hours:02d}:{minutes:02d}:{seconds:02d}")

    def start_scan(self):
        target_name = self.target_name_entry.text().strip()
        scope_file = getattr(self, 'scope_file_path', None)
        if not target_name or not scope_file: QMessageBox.warning(self, "Input Error", "Please provide a target name and select a scope file."); return
        self.output_log.clear(); self.output_files_list.clear(); self.start_button.setEnabled(False); self.stop_button.setEnabled(True); self.manage_button.setEnabled(False)
        commands = command_db.get_all_commands(); total_commands = len(commands)
        self.progress_bar.setMaximum(total_commands); self.progress_bar.setValue(0); self.progress_bar.setFormat(f"Step 0/{total_commands}"); self.progress_bar.setVisible(True)
        self.elapsed_time = 0; self.timer_label.setText("Elapsed Time: 00:00:00"); self.timer_label.setVisible(True); self.scan_timer.start(1000)
        self.worker = Worker(target_name=target_name, scope_file=scope_file, working_directory=self.working_directory, total_commands=total_commands)
        self.worker.progress.connect(self.update_log); self.worker.progress_updated.connect(self.update_progress_bar); self.worker.scan_updated.connect(self.refresh_output_files)
        self.worker.finished.connect(self.scan_finished); self.worker.error.connect(self.show_error_message); self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning(): self.worker.stop()
        self.scan_timer.stop()

    def update_log(self, message):
        html_message = self.ansi_to_html(message)
        self.output_log.append(html_message)

    def scan_finished(self):
        self.refresh_output_files(); self.scan_timer.stop()
        if self.worker and self.worker.is_running: self.progress_bar.setValue(self.progress_bar.maximum()); self.progress_bar.setFormat("Scan Completed")
        else: self.progress_bar.setFormat("Scan Cancelled")
        self.start_button.setEnabled(True); self.stop_button.setEnabled(False); self.manage_button.setEnabled(True); self.worker = None

    def show_error_message(self, message):
        self.update_log(f"[!!!] ERROR: {message}"); QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        if self.worker:
            for proc in self.worker.background_processes:
                try: proc.terminate()
                except Exception: pass
            if self.worker.isRunning(): self.worker.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    command_db.initialize_db() 
    working_dir = QFileDialog.getExistingDirectory(None, "Select a Working Directory", os.path.expanduser("~"))
    if not working_dir:
        sys.exit(0)

    domains_dialog = DomainsFileDialog(working_directory=working_dir)
    if domains_dialog.exec_() == QDialog.Accepted:
        domains_file = domains_dialog.domains_file_path
        main_win = ReconAutomatorApp(working_directory=working_dir, domains_file=domains_file)
        main_win.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)
