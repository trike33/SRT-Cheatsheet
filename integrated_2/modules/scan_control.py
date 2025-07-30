import os
import re
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QFileDialog, QMessageBox, QProgressBar
)
from PyQt5.QtCore import pyqtSignal, QTimer, QSize
from PyQt5.QtGui import QFont, QIcon

from utils import db as command_db
from utils.worker import Worker
from modules.dialogs import DomainsFileDialog, CommandEditorDialog
from modules.background_tasks import BackgroundTasksDialog

class ScanControlWidget(QWidget):
    """
    The main widget for the 'Scan Control' tab. It manages all scan-related
    UI and logic, including the background tasks dialog.
    """
    scan_updated = pyqtSignal()
    cwd_changed = pyqtSignal(str)
    theme_changed = pyqtSignal()
    background_task_started = pyqtSignal(int, str)

    def __init__(self, working_directory, icon_path, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.icon_path = icon_path
        self.worker = None
        self.current_font_size = 10
        self.scope_file_path = None

        main_layout = QVBoxLayout(self)
        top_bar_layout = QHBoxLayout()
        self.cwd_label = QLabel(f"CWD: {self.working_directory}")
        self.cwd_label.setStyleSheet("font-size: 9pt; color: grey;")
        top_bar_layout.addWidget(self.cwd_label)
        change_cwd_button = QPushButton("Change CWD")
        change_cwd_button.clicked.connect(self.change_working_directory)
        top_bar_layout.addWidget(change_cwd_button)
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
        setup_domains_button = QPushButton("Setup Domains File")
        setup_domains_button.clicked.connect(self.setup_domains_file)
        browse_scope_button = QPushButton("Browse Scope File")
        browse_scope_button.clicked.connect(self.browse_scope_file)
        input_layout.addWidget(QLabel("Target Name:"))
        input_layout.addWidget(self.target_name_entry)
        input_layout.addWidget(QLabel("Scope File:"))
        input_layout.addWidget(self.scope_file_label, 1)
        input_layout.addWidget(setup_domains_button)
        input_layout.addWidget(browse_scope_button)
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
        self.bg_tasks_button = QPushButton("View Background Tasks (0)")
        self.bg_tasks_button.clicked.connect(self.show_background_tasks)
        button_layout.addWidget(self.manage_button)
        button_layout.addWidget(self.bg_tasks_button)
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
        
        log_layout = QVBoxLayout()
        zoom_layout = QHBoxLayout()
        zoom_layout.addStretch()
        zoom_in_btn = QPushButton("+"); zoom_in_btn.setFixedWidth(30)
        zoom_in_btn.clicked.connect(lambda: self.zoom_log(1))
        zoom_out_btn = QPushButton("-"); zoom_out_btn.setFixedWidth(30)
        zoom_out_btn.clicked.connect(lambda: self.zoom_log(-1))
        zoom_layout.addWidget(zoom_out_btn)
        zoom_layout.addWidget(zoom_in_btn)
        log_layout.addLayout(zoom_layout)
        self.output_log = QTextEdit(readOnly=True)
        self.output_log.setFont(QFont("Courier", self.current_font_size))
        log_layout.addWidget(self.output_log)
        main_layout.addLayout(log_layout)

        self.bg_tasks_dialog = BackgroundTasksDialog(self)
        self.background_task_started.connect(self.bg_tasks_dialog.add_background_task)
        self.bg_tasks_dialog.task_termination_requested.connect(self.terminate_selected_bg_task)
        self.bg_monitor_timer = QTimer(self)
        self.bg_monitor_timer.timeout.connect(self.monitor_background_tasks)
        self.bg_monitor_timer.start(5000)

    def apply_theme(self, theme_name):
        sun_icon = QIcon(os.path.join(self.icon_path, "sun.svg"))
        moon_icon = QIcon(os.path.join(self.icon_path, "moon.svg"))
        if theme_name == 'dark':
            self.theme_button.setIcon(sun_icon)
            self.theme_button.setToolTip("Switch to Light Mode")
        else:
            self.theme_button.setIcon(moon_icon)
            self.theme_button.setToolTip("Switch to Dark Mode")

    def toggle_theme(self):
        command_db.toggle_theme()
        self.theme_changed.emit()

    def change_working_directory(self):
        new_dir = QFileDialog.getExistingDirectory(self, "Select New Working Directory", self.working_directory)
        if new_dir and new_dir != self.working_directory:
            self.cwd_changed.emit(new_dir)

    def browse_scope_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Scope File", self.working_directory)
        if file_path:
            self.scope_file_path = file_path
            self.scope_file_label.setText(os.path.basename(file_path))

    def setup_domains_file(self):
        target_name = self.target_name_entry.text().strip()
        if not target_name:
            QMessageBox.warning(self, "Target Name Required", "Please enter a Target Name before setting up the domains file.")
            return
        target_dir = os.path.join(self.working_directory, target_name)
        if not os.path.exists(target_dir):
            try:
                os.makedirs(target_dir)
                self.update_log(f"[*] Created directory for target: {target_dir}")
                self.scan_updated.emit()
            except OSError as e:
                self.show_error_message(f"Could not create target directory: {e}")
                return
        dialog = DomainsFileDialog(working_directory=target_dir)
        dialog.exec_()

    def open_command_editor(self):
        dialog = CommandEditorDialog(self)
        dialog.exec_()

    def zoom_log(self, direction):
        self.current_font_size += direction
        if self.current_font_size < 6: self.current_font_size = 6
        self.output_log.setFont(QFont("Courier", self.current_font_size))

    def ansi_to_html(self, text):
        color_map = {'30': 'black', '31': 'red', '32': 'green', '33': 'yellow', '34': 'blue', '35': 'magenta', '36': 'cyan', '37': 'white', '90': 'grey', '91': 'lightcoral', '92': 'lightgreen', '93': 'lightyellow', '94': 'lightblue', '95': 'lightpink', '96': 'lightcyan'}
        def replace_color(match): return f'<span style="color:{color_map.get(match.group(1), "white")}">'
        html = re.sub(r'\x1b\[(\d+)m', replace_color, text)
        html = html.replace('\x1b[0m', '</span>')
        if html.count('<span') > html.count('</span>'):
            html += '</span>' * (html.count('<span') - html.count('</span>'))
        return html.replace('\n', '<br>')

    def update_progress_bar(self, current_step, total_steps):
        self.progress_bar.setValue(current_step)
        self.progress_bar.setFormat(f"Step {current_step}/{total_steps}")

    def update_timer_display(self):
        self.elapsed_time += 1
        hours, rem = divmod(self.elapsed_time, 3600)
        minutes, seconds = divmod(rem, 60)
        self.timer_label.setText(f"Elapsed Time: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")

    def start_scan(self):
        target_name = self.target_name_entry.text().strip()
        if not target_name or not self.scope_file_path:
            QMessageBox.warning(self, "Input Error", "Please provide a target name and select a scope file.")
            return

        self.output_log.clear()
        self.start_button.setEnabled(False); self.stop_button.setEnabled(True); self.manage_button.setEnabled(False)
        
        commands = command_db.get_all_commands()
        total_commands = len(commands)
        
        self.progress_bar.setMaximum(total_commands); self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"Step 0/{total_commands}"); self.progress_bar.setVisible(True)
        
        self.elapsed_time = 0; self.timer_label.setText("Elapsed Time: 00:00:00"); self.timer_label.setVisible(True)
        self.scan_timer.start(1000)
        
        self.worker = Worker(target_name=target_name, scope_file=self.scope_file_path, working_directory=self.working_directory)
        self.worker.progress.connect(self.update_log)
        self.worker.progress_updated.connect(self.update_progress_bar)
        self.worker.scan_updated.connect(self.scan_updated)
        self.worker.background_task_started.connect(self.background_task_started)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(self.show_error_message)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
        self.scan_timer.stop()

    def update_log(self, message):
        html_message = self.ansi_to_html(message)
        self.output_log.append(html_message)

    def scan_finished(self):
        self.scan_timer.stop()
        if self.worker and self.worker.is_running:
            self.progress_bar.setValue(self.progress_bar.maximum())
            self.progress_bar.setFormat("Scan Completed")
        else:
            self.progress_bar.setFormat("Scan Cancelled")
        self.start_button.setEnabled(True); self.stop_button.setEnabled(False); self.manage_button.setEnabled(True)
        self.worker = None

    def show_error_message(self, message):
        self.update_log(f"[!!!] ERROR: {message}")
        QMessageBox.critical(self, "Error", message)

    def add_background_task(self, pid, command):
        self.bg_tasks_dialog.add_background_task(pid, command)
        self.update_bg_task_button_count()

    def terminate_selected_bg_task(self, pid):
        if self.worker and pid in self.worker.background_processes:
            try:
                self.worker.background_processes[pid].terminate()
                self.update_log(f"[!] Manually terminated background task [PID: {pid}].")
            except Exception as e:
                self.show_error_message(f"Could not terminate process {pid}: {e}")
        else:
            self.show_error_message(f"Could not find active process with PID {pid}.")

    def monitor_background_tasks(self):
        if not self.worker or not self.worker.background_processes:
            self.update_bg_task_button_count()
            return
        finished_pids = []
        for pid, proc in list(self.worker.background_processes.items()):
            if proc.poll() is not None:
                finished_pids.append(pid)
        for pid in finished_pids:
            if pid in self.worker.background_processes:
                del self.worker.background_processes[pid]
            self.bg_tasks_dialog.remove_background_task(pid)
            self.update_log(f"[✔] Background task [PID: {pid}] finished.")
        self.update_bg_task_button_count()
    
    def show_background_tasks(self):
        self.bg_tasks_dialog.setStyleSheet(self.window().styleSheet())
        self.bg_tasks_dialog.show()
    
    def update_bg_task_button_count(self):
        count = 0
        if self.worker and self.worker.background_processes:
            count = len(self.worker.background_processes)
        self.bg_tasks_button.setText(f"View Background Tasks ({count})")