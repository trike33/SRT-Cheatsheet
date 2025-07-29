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
import playground_view
import custom_command_view # Import the new terminal module

class DomainsFileDialog(QDialog):
    """A dialog to create, edit, and save a domains file."""
    def __init__(self, working_directory, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory; self.domains_file_path = ""
        self.setWindowTitle("Setup Domains File"); self.setMinimumSize(500, 400)
        layout = QVBoxLayout(self); layout.addWidget(QLabel("Enter domains (one per line) or open an existing file."))
        self.text_editor = QTextEdit(); layout.addWidget(self.text_editor)
        button_layout = QHBoxLayout(); browse_button = QPushButton("Open Existing File"); browse_button.clicked.connect(self.browse_file)
        button_layout.addWidget(browse_button); button_layout.addStretch()
        self.button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel); self.button_box.button(QDialogButtonBox.Save).setText("Save and Close")
        self.button_box.accepted.connect(self.save_and_accept); self.button_box.rejected.connect(self.reject); button_layout.addWidget(self.button_box)
        layout.addLayout(button_layout)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Domains File", self.working_directory, "Text Files (*.txt);;All Files (*)")
        if path:
            self.domains_file_path = path
            try:
                with open(path, 'r') as f: self.text_editor.setText(f.read())
                self.setWindowTitle(f"Editing: {os.path.basename(path)}")
            except Exception as e: QMessageBox.critical(self, "Error", f"Could not read file: {e}")

    def save_and_accept(self):
        if not self.domains_file_path:
            path, _ = QFileDialog.getSaveFileName(self, "Save Domains File As", os.path.join(self.working_directory, "domains"), "Text Files (*.txt);;All Files (*)")
            if not path: return
            self.domains_file_path = path
        try:
            with open(self.domains_file_path, 'w') as f: f.write(self.text_editor.toPlainText())
            self.accept()
        except Exception as e: QMessageBox.critical(self, "Error", f"Could not save file: {e}")

class CommandEditorDialog(QDialog):
    """Dialog for managing commands in the database (CRUD operations)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage Commands"); self.setGeometry(150, 150, 800, 500); self.setModal(True)
        layout = QVBoxLayout(self); self.table = QTableWidget(); self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Execution Order", "Command Text", "Use Shell", "Background"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setColumnHidden(0, True); self.table.setColumnWidth(1, 120); self.table.setColumnWidth(2, 450); self.table.setColumnWidth(3, 80); self.table.setColumnWidth(4, 80)
        layout.addWidget(self.table)
        button_layout = QHBoxLayout(); add_btn, edit_btn, delete_btn = QPushButton("Add New"), QPushButton("Edit Selected"), QPushButton("Delete Selected")
        add_btn.clicked.connect(self.add_row); edit_btn.clicked.connect(self.edit_row); delete_btn.clicked.connect(self.delete_row)
        button_layout.addStretch(); button_layout.addWidget(add_btn); button_layout.addWidget(edit_btn); button_layout.addWidget(delete_btn)
        layout.addLayout(button_layout); self.load_commands()

    def load_commands(self):
        self.table.setRowCount(0)
        for cmd in command_db.get_all_commands():
            row = self.table.rowCount(); self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(cmd['id']))); self.table.setItem(row, 1, QTableWidgetItem(str(cmd['execution_order']))); self.table.setItem(row, 2, QTableWidgetItem(cmd['command_text']))
            shell_check = QTableWidgetItem(); shell_check.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled); shell_check.setCheckState(Qt.Checked if cmd['use_shell'] else Qt.Unchecked); self.table.setItem(row, 3, shell_check)
            bg_check = QTableWidgetItem(); bg_check.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled); bg_check.setCheckState(Qt.Checked if cmd['run_in_background'] else Qt.Unchecked); self.table.setItem(row, 4, bg_check)

    def add_row(self):
        dialog = CommandInputDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data(); command_db.add_command(data['text'], data['shell'], data['order'], data['background']); self.load_commands()

    def edit_row(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected: return
        row = selected[0].row(); cmd_id = int(self.table.item(row, 0).text())
        current_data = {'id': cmd_id, 'order': int(self.table.item(row, 1).text()), 'text': self.table.item(row, 2).text(), 'shell': self.table.item(row, 3).checkState() == Qt.Checked, 'background': self.table.item(row, 4).checkState() == Qt.Checked}
        dialog = CommandInputDialog(self, data=current_data)
        if dialog.exec_() == QDialog.Accepted:
            new_data = dialog.get_data(); command_db.update_command(cmd_id, new_data['text'], new_data['shell'], new_data['order'], new_data['background']); self.load_commands()

    def delete_row(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected: return
        row = selected[0].row(); cmd_id = int(self.table.item(row, 0).text())
        if QMessageBox.question(self, "Confirm Deletion", "Are you sure you want to delete this command?") == QMessageBox.Yes:
            command_db.delete_command(cmd_id); self.load_commands()

class CommandInputDialog(QDialog):
    """Dialog for entering or editing a single command's details."""
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Command" if data else "Add Command")
        layout = QVBoxLayout(self)
        self.order_input = QSpinBox(); self.order_input.setRange(1, 9999); self.order_input.setSingleStep(10)
        layout.addWidget(QLabel("Execution Order:")); layout.addWidget(self.order_input)
        self.text_input = QLineEdit(); layout.addWidget(QLabel("Command Text (e.g., 'subfinder -d {target_name}' or 'internal:run_ipparser'):")); layout.addWidget(self.text_input)
        checkbox_layout = QHBoxLayout(); self.shell_check = QCheckBox("Requires Shell (for pipes, etc.)"); self.background_check = QCheckBox("Run in Background")
        checkbox_layout.addWidget(self.shell_check); checkbox_layout.addWidget(self.background_check); layout.addLayout(checkbox_layout)
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel); self.button_box.accepted.connect(self.accept); self.button_box.rejected.connect(self.reject); layout.addWidget(self.button_box)
        if data:
            self.order_input.setValue(data['order']); self.text_input.setText(data['text']); self.shell_check.setChecked(data['shell']); self.background_check.setChecked(data['background'])

    def get_data(self):
        return {'order': self.order_input.value(), 'text': self.text_input.text().strip(), 'shell': self.shell_check.isChecked(), 'background': self.background_check.isChecked()}

class Worker(QThread):
    """Worker thread to run the reconnaissance commands."""
    progress = pyqtSignal(str); progress_updated = pyqtSignal(int, int); scan_updated = pyqtSignal(); background_task_started = pyqtSignal(int, str); finished = pyqtSignal(); error = pyqtSignal(str)
    def __init__(self, target_name, scope_file, working_directory, total_commands):
        super().__init__(); self.target_name = target_name; self.scope_file = scope_file; self.working_directory = working_directory; self.total_commands = total_commands
        self.is_running = True; self.output_dir = os.path.join(self.working_directory, self.target_name); self.background_processes = {}

    def stop(self):
        self.is_running = False; self.progress.emit("--- Scan cancelled by user. ---")
        for pid, proc in list(self.background_processes.items()):
            try: proc.terminate(); self.progress.emit(f"[!] Terminated background process {pid}.")
            except Exception as e: self.progress.emit(f"[!] Could not terminate background process {pid}: {e}")
        self.terminate(); self.wait()

    def run_background_command(self, command_text, use_shell):
        self.progress.emit(f"[+] Starting background command: {command_text}")
        try:
            process_args = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL, 'cwd': self.output_dir}
            if use_shell: process_args['shell'] = True; proc = subprocess.Popen(command_text, **process_args)
            else: process_args['shell'] = False; proc = subprocess.Popen(shlex.split(command_text), **process_args)
            self.background_processes[proc.pid] = proc; self.background_task_started.emit(proc.pid, command_text); return True
        except Exception as e: self.error.emit(f"Failed to start background command '{command_text}': {e}"); return False

    def run_internal_command(self, command_text):
        self.progress.emit(f"[+] Running internal function: {command_text}"); parts = shlex.split(command_text); func_name = parts[0].split(':')[1]
        try:
            if func_name == 'run_ipparser':
                success, message = recon_tools.run_ipparser(scope_file_path=self.scope_file, output_dir=self.output_dir)
                if success: self.progress.emit(f"[✔] {message}"); return success, None
            parser = argparse.ArgumentParser(description=f'Parser for {func_name}')
            if func_name == 'run_domain_extracter':
                parser.add_argument('--input', required=True); parser.add_argument('--output', required=True); args = parser.parse_args(parts[1:])
                success, message = recon_tools.run_domain_extracter(input_file_path=os.path.join(self.output_dir, args.input), output_file_path=os.path.join(self.output_dir, args.output))
                if success: self.progress.emit(f"[✔] {message}"); return success, None
            elif func_name == 'run_domain_enum':
                parser.add_argument('--subdomains', required=True); parser.add_argument('--scope', required=True); parser.add_argument('--output', required=True); args = parser.parse_args(parts[1:])
                success, message = recon_tools.run_domain_enum(subdomains_file_path=os.path.join(self.output_dir, args.subdomains), scope_file_path=os.path.join(self.output_dir, args.scope), output_file_path=os.path.join(self.output_dir, args.output))
                if success: self.progress.emit(f"[✔] {message}"); return success, None
            elif func_name == 'run_format_ips':
                parser.add_argument('--input', required=True); args = parser.parse_args(parts[1:])
                success, message = recon_tools.run_format_ips(input_file_path=os.path.join(self.output_dir, args.input))
                if success: self.progress.emit(f"[✔] IP Formatter prepared data for piping."); return success, message
            else: self.error.emit(f"Unknown internal function: {func_name}"); return False, None
        except Exception as e: self.error.emit(f"Error processing internal function '{func_name}': {e}"); return False, None

    def run_external_command(self, command_text, use_shell, pipe_input=None):
        self.progress.emit(f"[+] Running: {command_text}")
        try:
            process_args = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'text': True, 'cwd': self.output_dir}
            if pipe_input: process_args['stdin'] = subprocess.PIPE
            if use_shell: process_args['shell'] = True; process = subprocess.Popen(command_text, **process_args)
            else: process_args['shell'] = False; process = subprocess.Popen(shlex.split(command_text), **process_args)
            if pipe_input: process.stdin.write(pipe_input); process.stdin.close()
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    if not self.is_running: process.terminate(); break
                    self.progress.emit(line.strip())
                process.stdout.close()
            return_code = process.wait(); stderr_output = process.stderr.read()
            if stderr_output: self.progress.emit(f"[!] Stderr: {stderr_output.strip()}")
            if return_code != 0: self.progress.emit(f"[!] Command failed: {command_text}"); return False
            self.progress.emit(f"[✔] Finished: {command_text}"); return True
        except Exception as e: self.error.emit(f"Failed to execute command '{command_text}': {e}"); return False

    def run(self):
        if not os.path.exists(self.output_dir):
            try: os.makedirs(self.output_dir)
            except OSError as e: self.error.emit(f"Fatal: Could not create target directory: {e}"); self.finished.emit(); return
        self.scan_updated.emit()
        commands = command_db.get_all_commands()
        if not commands: self.error.emit("No commands found in the database."); self.finished.emit(); return
        for i, cmd in enumerate(commands):
            if not self.is_running: break
            command_text, use_shell, run_in_bg = cmd['command_text'], cmd['use_shell'], cmd['run_in_background']
            success = False
            if run_in_bg: success = self.run_background_command(command_text, use_shell)
            elif '|' in command_text and use_shell:
                parts = command_text.split('|', 1); first_cmd, second_cmd = parts[0].strip(), parts[1].strip()
                if first_cmd.startswith('internal:'):
                    succ, pipe_input = self.run_internal_command(first_cmd)
                    if succ: success = self.run_external_command(second_cmd, use_shell, pipe_input=pipe_input)
                else: success = self.run_external_command(command_text, use_shell)
            elif command_text.startswith('internal:'): success, _ = self.run_internal_command(command_text)
            else: success = self.run_external_command(command_text, use_shell)
            if success: self.scan_updated.emit(); self.progress_updated.emit(i + 1, self.total_commands)
            else: self.error.emit("Stopping scan due to command failure."); break
        if self.is_running: self.progress.emit("\n[***] Main scan sequence completed. Background tasks may still be running. [***]")
        self.finished.emit()

class ReconAutomatorApp(QMainWindow):
    """Main application window."""
    def __init__(self, working_directory):
        super().__init__(); self.setWindowTitle("Reconnaissance Automator"); self.setGeometry(100, 100, 1000, 800)
        self.working_directory = working_directory; self.worker = None; self.current_font_size = 10
        self.create_icons(); self.tabs = QTabWidget(); self.setCentralWidget(self.tabs)
        scan_control_widget = QWidget(); self.tabs.addTab(scan_control_widget, "Scan Control"); main_layout = QVBoxLayout(scan_control_widget)
        top_bar_layout = QHBoxLayout(); top_bar_layout.addStretch(); self.theme_button = QPushButton(); self.theme_button.setFlat(True); self.theme_button.setIconSize(QSize(24, 24)); self.theme_button.clicked.connect(self.toggle_theme); top_bar_layout.addWidget(self.theme_button); main_layout.addLayout(top_bar_layout)
        input_layout = QHBoxLayout(); self.target_name_entry = QLineEdit(); self.scope_file_label = QLabel("No file selected")
        setup_domains_button = QPushButton("Setup Domains File"); setup_domains_button.clicked.connect(self.setup_domains_file)
        browse_scope_button = QPushButton("Browse Scope File"); browse_scope_button.clicked.connect(self.browse_scope_file)
        input_layout.addWidget(QLabel("Target Name:")); input_layout.addWidget(self.target_name_entry); input_layout.addWidget(QLabel("Scope File:")); input_layout.addWidget(self.scope_file_label, 1); input_layout.addWidget(setup_domains_button); input_layout.addWidget(browse_scope_button); main_layout.addLayout(input_layout)
        button_layout = QHBoxLayout(); self.start_button = QPushButton("Start Scan"); self.start_button.setObjectName("StartButton"); self.start_button.clicked.connect(self.start_scan); self.stop_button = QPushButton("Stop Scan", enabled=False); self.stop_button.setObjectName("StopButton"); self.stop_button.clicked.connect(self.stop_scan); self.manage_button = QPushButton("Manage Commands"); self.manage_button.clicked.connect(self.open_command_editor); button_layout.addWidget(self.manage_button); button_layout.addStretch(); button_layout.addWidget(self.start_button); button_layout.addWidget(self.stop_button); main_layout.addLayout(button_layout)
        progress_layout = QHBoxLayout(); self.progress_bar = QProgressBar(); self.progress_bar.setVisible(False); self.timer_label = QLabel("Elapsed Time: 00:00:00"); self.timer_label.setVisible(False); progress_layout.addWidget(self.progress_bar); progress_layout.addWidget(self.timer_label); main_layout.addLayout(progress_layout)
        self.scan_timer = QTimer(self); self.scan_timer.timeout.connect(self.update_timer_display); self.elapsed_time = 0
        log_layout = QVBoxLayout(); zoom_layout = QHBoxLayout(); zoom_layout.addStretch(); zoom_in_btn = QPushButton("+"); zoom_in_btn.setFixedWidth(30); zoom_in_btn.clicked.connect(lambda: self.zoom_log(1)); zoom_out_btn = QPushButton("-"); zoom_out_btn.setFixedWidth(30); zoom_out_btn.clicked.connect(lambda: self.zoom_log(-1)); zoom_layout.addWidget(zoom_out_btn); zoom_layout.addWidget(zoom_in_btn); log_layout.addLayout(zoom_layout)
        self.output_log = QTextEdit(readOnly=True); self.output_log.setFont(QFont("Courier", self.current_font_size)); log_layout.addWidget(self.output_log); main_layout.addLayout(log_layout)
        
        playground_tab = QWidget(); self.tabs.addTab(playground_tab, "Playground"); playground_layout = QVBoxLayout(playground_tab)
        self.playground_list = QListWidget(); self.playground_list.setViewMode(QListWidget.IconMode); self.playground_list.setIconSize(QSize(64, 64)); self.playground_list.setSpacing(15); self.playground_list.itemDoubleClicked.connect(self.open_playground_item)
        playground_layout.addWidget(self.playground_list)
        
        self.terminal_tab = custom_command_view.CustomCommandWidget(working_directory=self.working_directory)
        self.tabs.addTab(self.terminal_tab, "Terminal")

        bg_tasks_widget = QWidget(); self.tabs.addTab(bg_tasks_widget, "Background Tasks"); bg_layout = QVBoxLayout(bg_tasks_widget); self.bg_tasks_list = QListWidget(); bg_layout.addWidget(self.bg_tasks_list); bg_button_layout = QHBoxLayout(); bg_button_layout.addStretch(); terminate_btn = QPushButton("Terminate Selected Task"); terminate_btn.clicked.connect(self.terminate_selected_bg_task); bg_button_layout.addWidget(terminate_btn); bg_layout.addLayout(bg_button_layout)
        self.bg_monitor_timer = QTimer(self); self.bg_monitor_timer.timeout.connect(self.monitor_background_tasks); self.bg_monitor_timer.start(5000)
        self.apply_theme()
        self.refresh_playground()
    def create_icons(self):
        sun_svg = b'<svg ...>...</svg>'; moon_svg = b'<svg ...>...</svg>'; file_svg = b'<svg ...>...</svg>' # Omitted for brevity
        folder_svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>'
        add_svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>'
        sun_pixmap = QPixmap(); sun_pixmap.loadFromData(sun_svg); self.sun_icon = QIcon(sun_pixmap)
        moon_pixmap = QPixmap(); moon_pixmap.loadFromData(moon_svg); self.moon_icon = QIcon(moon_pixmap)
        file_pixmap = QPixmap(); file_pixmap.loadFromData(file_svg); self.file_icon = QIcon(file_pixmap)
        folder_pixmap = QPixmap(); folder_pixmap.loadFromData(folder_svg); self.folder_icon = QIcon(folder_pixmap)
        add_pixmap = QPixmap(); add_pixmap.loadFromData(add_svg); self.add_icon = QIcon(add_pixmap)

    def zoom_log(self, direction):
        self.current_font_size += direction
        if self.current_font_size < 6: self.current_font_size = 6
        self.output_log.setFont(QFont("Courier", self.current_font_size))

    def ansi_to_html(self, text):
        color_map = {'30': 'black', '31': 'red', '32': 'green', '33': 'yellow', '34': 'blue', '35': 'magenta', '36': 'cyan', '37': 'white', '90': 'grey', '91': 'lightcoral', '92': 'lightgreen', '93': 'lightyellow', '94': 'lightblue', '95': 'lightpink', '96': 'lightcyan'}
        def replace_color(match): return f'<span style="color:{color_map.get(match.group(1), "white")}">'
        html = re.sub(r'\x1b\[(\d+)m', replace_color, text); html = html.replace('\x1b[0m', '</span>')
        if html.count('<span') > html.count('</span>'): html += '</span>' * (html.count('<span') - html.count('</span>'))
        return html.replace('\n', '<br>')

    def apply_theme(self):
        theme_name = command_db.get_setting('active_theme'); stylesheet = command_db.get_setting(f"{theme_name}_theme_stylesheet"); self.setStyleSheet(stylesheet)
        if theme_name == 'dark': self.theme_button.setIcon(self.sun_icon); self.theme_button.setToolTip("Switch to Light Mode")
        else: self.theme_button.setIcon(self.moon_icon); self.theme_button.setToolTip("Switch to Dark Mode")

    def toggle_theme(self):
        current_theme = command_db.get_setting('active_theme'); new_theme = 'light' if current_theme == 'dark' else 'dark'
        command_db.update_setting('active_theme', new_theme); self.apply_theme()

    def open_command_editor(self): CommandEditorDialog(self).exec_()
    def browse_scope_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Scope File", self.working_directory)
        if file_path: self.scope_file_path = file_path; self.scope_file_label.setText(os.path.basename(file_path))

    def setup_domains_file(self):
        target_name = self.target_name_entry.text().strip()
        if not target_name: QMessageBox.warning(self, "Target Name Required", "Please enter a Target Name before setting up the domains file."); return
        target_dir = os.path.join(self.working_directory, target_name)
        if not os.path.exists(target_dir):
            try: os.makedirs(target_dir); self.update_log(f"[*] Created directory for target: {target_dir}"); self.refresh_playground()
            except OSError as e: self.show_error_message(f"Could not create target directory: {e}"); return
        domains_dialog = DomainsFileDialog(working_directory=target_dir); domains_dialog.exec_()

    def refresh_playground(self):
        self.playground_list.clear()
        add_item = QListWidgetItem(self.add_icon, "Add Existing Folder"); add_item.setData(Qt.UserRole, "add_folder_action"); self.playground_list.addItem(add_item)
        try:
            for item_name in sorted(os.listdir(self.working_directory)):
                if os.path.isdir(os.path.join(self.working_directory, item_name)):
                    folder_item = QListWidgetItem(self.folder_icon, item_name); folder_item.setData(Qt.UserRole, os.path.join(self.working_directory, item_name)); self.playground_list.addItem(folder_item)
        except OSError as e: self.show_error_message(f"Could not read working directory: {e}")

    def open_playground_item(self, item):
        role_data = item.data(Qt.UserRole)
        if role_data == "add_folder_action":
            folder = QFileDialog.getExistingDirectory(self, "Select Existing Target Folder", self.working_directory)
            if folder:
                for i in range(self.playground_list.count()):
                    if self.playground_list.item(i).data(Qt.UserRole) == folder: return
                folder_item = QListWidgetItem(self.folder_icon, os.path.basename(folder)); folder_item.setData(Qt.UserRole, folder); self.playground_list.addItem(folder_item)
        else:
            playground_win = playground_view.PlaygroundWindow(target_folder_path=role_data, file_icon=self.file_icon, parent=self); playground_win.exec_()

    def update_progress_bar(self, current_step, total_steps): self.progress_bar.setValue(current_step); self.progress_bar.setFormat(f"Step {current_step}/{total_steps}")
    def update_timer_display(self):
        self.elapsed_time += 1; hours = self.elapsed_time // 3600; minutes = (self.elapsed_time % 3600) // 60; seconds = self.elapsed_time % 60
        self.timer_label.setText(f"Elapsed Time: {hours:02d}:{minutes:02d}:{seconds:02d}")

    def add_background_task(self, pid, command):
        item = QListWidgetItem(f"[PID: {pid}] {command}"); item.setData(Qt.UserRole, pid); self.bg_tasks_list.addItem(item)

    def terminate_selected_bg_task(self):
        selected_items = self.bg_tasks_list.selectedItems()
        if not selected_items: QMessageBox.warning(self, "Selection Error", "Please select a background task to terminate."); return
        item = selected_items[0]; pid = item.data(Qt.UserRole)
        if self.worker and pid in self.worker.background_processes:
            try:
                self.worker.background_processes[pid].terminate(); self.update_log(f"[!] Manually terminated background task [PID: {pid}].")
            except Exception as e: self.show_error_message(f"Could not terminate process {pid}: {e}")
        else: self.show_error_message(f"Could not find active process with PID {pid}.")

    def monitor_background_tasks(self):
        if not self.worker or not self.worker.background_processes: return
        finished_pids = []
        for pid, proc in list(self.worker.background_processes.items()):
            if proc.poll() is not None: finished_pids.append(pid)
        for pid in finished_pids:
            del self.worker.background_processes[pid]
            for i in range(self.bg_tasks_list.count()):
                item = self.bg_tasks_list.item(i)
                if item and item.data(Qt.UserRole) == pid:
                    self.update_log(f"[✔] Background task finished: {item.text()}"); self.bg_tasks_list.takeItem(i); break

    def start_scan(self):
        target_name = self.target_name_entry.text().strip(); scope_file = getattr(self, 'scope_file_path', None)
        if not target_name or not scope_file: QMessageBox.warning(self, "Input Error", "Please provide a target name and select a scope file."); return
        self.output_log.clear(); self.bg_tasks_list.clear()
        self.start_button.setEnabled(False); self.stop_button.setEnabled(True); self.manage_button.setEnabled(False)
        commands = command_db.get_all_commands(); total_commands = len(commands)
        self.progress_bar.setMaximum(total_commands); self.progress_bar.setValue(0); self.progress_bar.setFormat(f"Step 0/{total_commands}"); self.progress_bar.setVisible(True)
        self.elapsed_time = 0; self.timer_label.setText("Elapsed Time: 00:00:00"); self.timer_label.setVisible(True); self.scan_timer.start(1000)
        self.worker = Worker(target_name=target_name, scope_file=scope_file, working_directory=self.working_directory, total_commands=total_commands)
        self.worker.progress.connect(self.update_log); self.worker.progress_updated.connect(self.update_progress_bar); self.worker.scan_updated.connect(self.refresh_playground)
        self.worker.background_task_started.connect(self.add_background_task)
        self.worker.finished.connect(self.scan_finished); self.worker.error.connect(self.show_error_message); self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning(): self.worker.stop()
        self.scan_timer.stop()

    def update_log(self, message):
        html_message = self.ansi_to_html(message); self.output_log.append(html_message)

    def scan_finished(self):
        self.refresh_playground(); self.scan_timer.stop()
        if self.worker and self.worker.is_running: self.progress_bar.setValue(self.progress_bar.maximum()); self.progress_bar.setFormat("Scan Completed")
        else: self.progress_bar.setFormat("Scan Cancelled")
        self.start_button.setEnabled(True); self.stop_button.setEnabled(False); self.manage_button.setEnabled(True); self.worker = None

    def show_error_message(self, message):
        self.update_log(f"[!!!] ERROR: {message}"); QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        # Also stop the terminal processes if they are running
        if hasattr(self, 'terminal_tab'):
            self.terminal_tab.stop_all_processes()
        if self.worker:
            if self.worker.isRunning(): self.worker.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    command_db.initialize_db() 
    working_dir = QFileDialog.getExistingDirectory(None, "Select a Working Directory", os.path.expanduser("~"))
    if working_dir:
        main_win = ReconAutomatorApp(working_directory=working_dir)
        main_win.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)
