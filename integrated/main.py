import datetime
from collections import deque 
import sys
import json
import uuid
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QTextEdit, QPushButton, QListWidget, QListWidgetItem,
    QMessageBox, QLabel, QSplitter, QComboBox, QInputDialog, QDialog,
    QDialogButtonBox, QAbstractItemView, QGroupBox, QStatusBar
)
from PyQt5.QtCore import QProcess, Qt, QTimer
from PyQt5.QtGui import QColor, QPalette, QTextCursor, QFont

# Import DatabaseManager from the new module
from modules.db import DatabaseManager

# --- Custom Dialog for Confirmations to ensure styling ---
class ConfirmDialog(QMessageBox):
    """A custom QMessageBox to ensure it respects the application's stylesheet."""
    def __init__(self, parent=None, title="Confirm", text="Are you sure?"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setText(text)
        self.setIcon(QMessageBox.Question)
        self.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        self.setDefaultButton(QMessageBox.No)

# --- Dialog for Creating/Editing Command Sequences ---
class CreateSequenceDialog(QDialog):
    def __init__(self, db_manager, existing_sequence=None, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.existing_sequence = existing_sequence
        self.init_ui()
        if self.existing_sequence:
            self.load_existing_sequence()

    def init_ui(self):
        """Initializes the UI for the sequence dialog."""
        self.setWindowTitle("Create/Edit Command Sequence")
        self.setGeometry(200, 200, 700, 600)
        main_layout = QVBoxLayout(self)

        # Sequence Name Input
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Sequence Name:"))
        self.sequence_name_input = QLineEdit()
        name_layout.addWidget(self.sequence_name_input)
        main_layout.addLayout(name_layout)

        # Commands in the sequence list
        sequence_group = QGroupBox("Commands in Sequence")
        sequence_layout = QVBoxLayout(sequence_group)
        self.sequence_commands_list = QListWidget()
        self.sequence_commands_list.setSelectionMode(QAbstractItemView.SingleSelection)
        sequence_layout.addWidget(self.sequence_commands_list)
        
        reorder_layout = QHBoxLayout()
        reorder_layout.addStretch()
        self.up_button = QPushButton("Move Up")
        self.up_button.clicked.connect(self.move_item_up)
        reorder_layout.addWidget(self.up_button)
        self.down_button = QPushButton("Move Down")
        self.down_button.clicked.connect(self.move_item_down)
        reorder_layout.addWidget(self.down_button)
        self.remove_button = QPushButton("Remove Selected Step")
        self.remove_button.clicked.connect(self.remove_selected_from_sequence)
        reorder_layout.addWidget(self.remove_button)
        sequence_layout.addLayout(reorder_layout)
        main_layout.addWidget(sequence_group)

        # GroupBox for adding new command steps
        add_step_group = QGroupBox("Add New Command Step")
        add_step_layout = QVBoxLayout(add_step_group)
        add_step_layout.addWidget(QLabel("Step Name (e.g., 'List Directory'):"))
        self.step_name_input = QLineEdit()
        add_step_layout.addWidget(self.step_name_input)
        add_step_layout.addWidget(QLabel("Command Text (e.g., 'ls -la'):"))
        self.step_command_input = QLineEdit()
        add_step_layout.addWidget(self.step_command_input)
        self.add_step_button = QPushButton("Add Step to Sequence")
        self.add_step_button.clicked.connect(self.add_step_to_sequence)
        add_step_layout.addWidget(self.add_step_button)
        main_layout.addWidget(add_step_group)

        # Dialog Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        main_layout.addWidget(self.button_box)

    def update_item_indices(self):
        """Updates the displayed text of items in the sequence list with indices."""
        for i in range(self.sequence_commands_list.count()):
            item = self.sequence_commands_list.item(i)
            data = item.data(Qt.UserRole)
            original_name = data.get('name', 'Unknown')
            item.setText(f"{i + 1}. {original_name}")

    def load_existing_sequence(self):
        seq_id, name, sequence_data = self.existing_sequence
        self.sequence_name_input.setText(name)
        for cmd_info in sequence_data:
            item = QListWidgetItem()
            item.setData(Qt.UserRole, cmd_info)
            self.sequence_commands_list.addItem(item)
        self.update_item_indices()

    def add_step_to_sequence(self):
        step_name = self.step_name_input.text().strip()
        step_command = self.step_command_input.text().strip()

        if not step_name or not step_command:
            QMessageBox.warning(self, "Input Error", "Step Name and Command Text cannot be empty.")
            return

        item = QListWidgetItem()
        # Use a unique ID for the step, though it's not strictly needed for this logic
        step_data = {'id': str(uuid.uuid4()), 'name': step_name, 'command': step_command}
        item.setData(Qt.UserRole, step_data)
        self.sequence_commands_list.addItem(item)
        self.update_item_indices()

        # Clear input fields for the next entry
        self.step_name_input.clear()
        self.step_command_input.clear()
        self.step_name_input.setFocus()

    def remove_selected_from_sequence(self):
        selected_items = self.sequence_commands_list.selectedItems()
        if not selected_items:
            return
        for item in selected_items:
            self.sequence_commands_list.takeItem(self.sequence_commands_list.row(item))
        self.update_item_indices()

    def move_item(self, direction):
        list_widget = self.sequence_commands_list
        current_row = list_widget.currentRow()
        if current_row < 0: return
        new_row = current_row + direction
        if 0 <= new_row < list_widget.count():
            item = list_widget.takeItem(current_row)
            list_widget.insertItem(new_row, item)
            list_widget.setCurrentRow(new_row)
            self.update_item_indices()

    def move_item_up(self):
        self.move_item(-1)

    def move_item_down(self):
        self.move_item(1)

    def get_sequence_data(self):
        name = self.sequence_name_input.text().strip()
        sequence_list = [self.sequence_commands_list.item(i).data(Qt.UserRole) for i in range(self.sequence_commands_list.count())]
        return name, sequence_list

# --- Main Application Window ---
class CommandExecutorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db_manager = DatabaseManager()
        self.running_processes = {}  # {exec_id: QProcess}
        self.command_queue = deque()  # (cmd_text, cmd_name, is_sequence_command, queued_exec_id)
        # -- Parallel slot state --
        self.parallel_limit = 4
        self.process_slots = [None]*self.parallel_limit       # (exec_id, process) or None
        self.process_exec_ids = [None]*self.parallel_limit
        self.timer_labels = []
        self.output_boxes = []
        self.timers = []
        self.timer_counters = []
        self.current_stdin_process_id = None
        # Sequence-related state
        self.active_sequence_commands = []
        self.current_sequence_index = -1
        self.sequence_execution_mode = False
        self.current_sequence_process = None
        # Themes
        self.current_theme_name = "Default Dark"
        self.define_stylesheets()
        self.init_ui()
        self.load_commands()
        self.load_themes()
        self.load_sequences()

    # --- THEMES (as in your original) -----------------
    def define_stylesheets(self):
        self.default_dark_stylesheet = (
            'QMainWindow { background: #232323; }'
            'QTextEdit, QLineEdit, QListWidget, QComboBox { color: #f0f0f0; background: #3c3c3c; }'
            'QPushButton { background: #444; color: #fff; }'
        )
        self.light_stylesheet = (
            'QMainWindow { background: #f7f7f7; }'
            'QTextEdit, QLineEdit, QListWidget, QComboBox { color: #333; background: #fff; }'
            'QPushButton { background: #ddd; color: #222; }'
        )

    def apply_styles(self, stylesheet):
        self.setStyleSheet(stylesheet)

    def load_themes(self):
        self.theme_combo_box.blockSignals(True)
        self.theme_combo_box.clear()
        if not self.db_manager.get_theme_by_name("Default Dark"):
            self.db_manager.add_theme("Default Dark", self.default_dark_stylesheet)
        if not self.db_manager.get_theme_by_name("Light Theme"):
            self.db_manager.add_theme("Light Theme", self.light_stylesheet)
        themes = self.db_manager.get_themes()
        for theme_id, name, sheet in themes:
            self.theme_combo_box.addItem(name, (theme_id, sheet))
        self.theme_combo_box.addItem("Save Current as New...")
        idx = self.theme_combo_box.findText(self.current_theme_name)
        if idx != -1:
            self.theme_combo_box.setCurrentIndex(idx)
            self.apply_styles(self.theme_combo_box.itemData(idx)[1])
        self.theme_combo_box.blockSignals(False)

    def change_theme(self, index):
        if index < 0:
            return
        if self.theme_combo_box.currentText() == "Save Current as New...":
            self.save_current_stylesheet_as_theme()
            prev = self.theme_combo_box.findText(self.current_theme_name)
            if prev != -1:
                self.theme_combo_box.setCurrentIndex(prev)
            return
        data = self.theme_combo_box.itemData(index)
        if data:
            self.current_theme_name = self.theme_combo_box.currentText()
            self.apply_styles(data[1])
            self.statusBar().showMessage(f"Theme changed to '{self.current_theme_name}'.")

    def save_current_stylesheet_as_theme(self):
        theme_name, ok = QInputDialog.getText(self, "Save Theme", "Enter name for the new theme:")
        if ok and theme_name:
            if self.db_manager.add_theme(theme_name.strip(), self.styleSheet()):
                self.statusBar().showMessage(f"Theme '{theme_name}' saved.")
                self.load_themes()
                idx = self.theme_combo_box.findText(theme_name)
                if idx != -1:
                    self.theme_combo_box.setCurrentIndex(idx)
            else:
                QMessageBox.warning(self, "Save Error", f"Theme name '{theme_name}' already exists.")

    # ------------- MAIN WINDOW / UI -----------------------
    def init_ui(self):
        self.setWindowTitle("Colorful Command Executor (4 Parallel Slots)")
        self.setGeometry(100, 100, 1300, 820)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        splitter = QSplitter(Qt.Horizontal)

        # -- Left panel (unchanged) --
        # (retain original logic for commands and sequences)
        left_widget = QWidget()
        left_panel = QVBoxLayout(left_widget)
        # --- Single Command Management ---
        command_group_box = QGroupBox("Single Command Management")
        command_layout = QVBoxLayout(command_group_box)
        self.command_name_input = QLineEdit(placeholderText="Enter command name...")
        command_layout.addWidget(QLabel("Command Name:"))
        command_layout.addWidget(self.command_name_input)
        self.command_text_input = QLineEdit(placeholderText="Enter command...")
        command_layout.addWidget(QLabel("Command Text:"))
        command_layout.addWidget(self.command_text_input)
        btn_layout = QHBoxLayout()
        self.execute_button = QPushButton("Execute Single", clicked=self.execute_command_from_input)
        self.save_button = QPushButton("Save Command", clicked=self.save_command)
        self.update_button = QPushButton("Update Command", clicked=self.update_command, enabled=False)
        btn_layout.addWidget(self.execute_button)
        btn_layout.addWidget(self.save_button)
        btn_layout.addWidget(self.update_button)
        command_layout.addLayout(btn_layout)

        delete_btn_layout = QHBoxLayout()
        self.delete_button = QPushButton("Delete Selected", clicked=self.delete_command, enabled=False)
        self.delete_all_commands_button = QPushButton("Delete All", clicked=self.delete_all_commands)
        delete_btn_layout.addWidget(self.delete_button)
        delete_btn_layout.addWidget(self.delete_all_commands_button)
        command_layout.addLayout(delete_btn_layout)

        command_layout.addWidget(QLabel("Saved Single Commands:"))
        self.command_list = QListWidget(itemClicked=self.load_selected_command)
        command_layout.addWidget(self.command_list)
        left_panel.addWidget(command_group_box)

        # --- Sequence Management ---
        sequence_group_box = QGroupBox("Sequence Management")
        sequence_layout = QVBoxLayout(sequence_group_box)
        seq_btn_layout = QHBoxLayout()
        self.create_sequence_button = QPushButton("Create New", clicked=self.create_sequence)
        self.edit_sequence_button = QPushButton("Edit Selected", clicked=self.edit_sequence, enabled=False)
        self.delete_sequence_button = QPushButton("Delete Selected", clicked=self.delete_sequence, enabled=False)
        seq_btn_layout.addWidget(self.create_sequence_button)
        seq_btn_layout.addWidget(self.edit_sequence_button)
        seq_btn_layout.addWidget(self.delete_sequence_button)
        sequence_layout.addLayout(seq_btn_layout)
        sequence_layout.addWidget(QLabel("Saved Sequences:"))
        self.sequence_list = QListWidget(itemClicked=self.load_selected_sequence_for_execution)
        sequence_layout.addWidget(self.sequence_list)
        self.execute_sequence_button = QPushButton("Execute Selected Sequence", clicked=self.execute_selected_sequence, enabled=False)
        sequence_layout.addWidget(self.execute_sequence_button)
        left_panel.addWidget(sequence_group_box)
        splitter.addWidget(left_widget)

        # ------- Right panel (NEW OUTPUT LOGIC) -------
        right_widget = QWidget()
        right_panel = QVBoxLayout(right_widget)
        # --- Output group for 4 parallel slots ---
        output_group = QGroupBox("Parallel Command Outputs")
        output_layout = QHBoxLayout(output_group)
        for i in range(self.parallel_limit):
            vbox = QVBoxLayout()
            timer_lbl = QLabel(f"Timer: 00:00.00")
            output_box = QTextEdit()
            output_box.setReadOnly(True)
            output_box.setFont(QFont("Consolas", 10))
            self.output_boxes.append(output_box)
            self.timer_labels.append(timer_lbl)
            vbox.addWidget(QLabel(f"Slot {i+1}"))
            vbox.addWidget(timer_lbl)
            vbox.addWidget(output_box)
            output_layout.addLayout(vbox)
            timer = QTimer()
            timer.setInterval(100)
            timer.timeout.connect(lambda idx=i: self.update_timer(idx))
            self.timers.append(timer)
            self.timer_counters.append(0.0)
        self.clear_outputs_button = QPushButton("Clear All Outputs", clicked=self.clear_all_outputs)
        output_layout.addWidget(self.clear_outputs_button)
        right_panel.addWidget(output_group)

                # --- Stdin line for the currently focused slot (slot 0 by default) ---
        self.stdin_input = QLineEdit(placeholderText="Stdin input for slot 1...", enabled=False, returnPressed=self.send_stdin)
        right_panel.addWidget(self.stdin_input)

        # --- Sequence Execution Controls ---
        self.sequence_control_group = QGroupBox("Sequence Execution Controls")
        self.sequence_control_group.setVisible(False)
        seq_ctrl_layout = QVBoxLayout(self.sequence_control_group)
        self.current_sequence_label = QLabel("Active Sequence: None")
        self.current_command_label = QLabel("Current Command: None")
        seq_ctrl_layout.addWidget(self.current_sequence_label)
        seq_ctrl_layout.addWidget(self.current_command_label)
        seq_nav_layout = QHBoxLayout()
        self.previous_command_button = QPushButton("Previous", clicked=self.run_previous_command_in_sequence)
        self.next_command_button = QPushButton("Next", clicked=self.run_next_command_in_sequence)
        seq_nav_layout.addWidget(self.previous_command_button)
        seq_nav_layout.addWidget(self.next_command_button)
        seq_ctrl_layout.addLayout(seq_nav_layout)
        jump_layout = QHBoxLayout()
        jump_layout.addWidget(QLabel("Jump To:"))
        self.jump_to_combo_box = QComboBox()
        self.jump_to_combo_box.currentIndexChanged.connect(self.jump_to_command_in_sequence)
        jump_layout.addWidget(self.jump_to_combo_box)
        seq_ctrl_layout.addLayout(jump_layout)
        self.stop_sequence_button = QPushButton("Stop Sequence", clicked=self.stop_current_sequence_execution)
        seq_ctrl_layout.addWidget(self.stop_sequence_button)
        right_panel.addWidget(self.sequence_control_group)

        # --- Theme chooser and STOP ALL ---
        bottom_controls_layout = QHBoxLayout()
        self.theme_combo_box = QComboBox(currentIndexChanged=self.change_theme)
        bottom_controls_layout.addWidget(QLabel("Theme:"))
        bottom_controls_layout.addWidget(self.theme_combo_box)
        bottom_controls_layout.addStretch()
        self.stop_all_button = QPushButton("Stop All Commands", clicked=self.stop_all_commands)
        bottom_controls_layout.addWidget(self.stop_all_button)
        right_panel.addLayout(bottom_controls_layout)

        splitter.addWidget(right_widget)
        splitter.setSizes([400, 800])
        main_layout.addWidget(splitter)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready")

    def clear_all_outputs(self):
        for box in self.output_boxes:
            box.clear()
        for t in self.timer_labels:
            t.setText("Timer: 00:00.00")
        for idx in range(self.parallel_limit):
            self.timer_counters[idx] = 0.0
            self.timers[idx].stop()
            self.process_slots[idx] = None
            self.process_exec_ids[idx] = None
        self.current_stdin_process_id = None
        self.stdin_input.setEnabled(False)

    def get_free_slot_index(self):
        for idx, slot in enumerate(self.process_slots):
            if slot is None:
                return idx
        return None

    def get_slot_index_for_execution_id(self, exec_id):
        for idx, eid in enumerate(self.process_exec_ids):
            if eid == exec_id:
                return idx
        return None

    def update_timer(self, idx):
        self.timer_counters[idx] += 0.1
        total = self.timer_counters[idx]
        mins = int(total // 60)
        secs = int(total % 60)
        hunds = int((total - int(total)) * 100)
        self.timer_labels[idx].setText(f"Timer: {mins:02d}:{secs:02d}.{hunds:02d}")

    # ------------- COMMAND ENGINE, PARALLEL SLOTS ---------
    def execute_command_from_input(self):
        name = self.command_name_input.text().strip()
        cmd = self.command_text_input.text().strip()
        self.execute_command(cmd, name)

    def execute_command(self, command_text, command_name, is_sequence_command=False, forced_slot=None, queued_execution_id=None):
        if not command_text:
            return
        slot_idx = forced_slot if forced_slot is not None else self.get_free_slot_index()
        if slot_idx is None:
            exec_id = queued_execution_id or f"{command_name or 'adhoc'}_{uuid.uuid4()}"
            self.command_queue.append((command_text, command_name, is_sequence_command, exec_id))
            self.output_boxes[0].append(f"<span style='color:orange'>Command '{command_name}' queued (parallel limit reached).</span>")
            return

        execution_id = queued_execution_id or f"{command_name or 'adhoc'}_{uuid.uuid4()}"
        color = "#87ceeb" if self.current_theme_name != "Light Theme" else "#1a73e8"
        self.output_boxes[slot_idx].append(f"<span style='color: {color};'>--- Executing: {command_name} ({command_text}) ---</span>")
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.MergedChannels)
        process.readyReadStandardOutput.connect(
            lambda idx=slot_idx, eid=execution_id: self.read_output(process, idx, eid))
        process.finished.connect(
            lambda exitCode, exitStatus, p=process, i=slot_idx, eid=execution_id, s=is_sequence_command:
                self.process_finished(p, eid, s, i))
        self.running_processes[execution_id] = process
        self.process_slots[slot_idx] = (execution_id, process)
        self.process_exec_ids[slot_idx] = execution_id
        self.timer_counters[slot_idx] = 0.0
        self.timers[slot_idx].start()
        # For stdin: assign the *first* started slot as input slot
        if self.current_stdin_process_id is None:
            self.current_stdin_process_id = execution_id
            self.stdin_input.setEnabled(True)
            self.stdin_input.setPlaceholderText(f"Stdin input for slot {slot_idx+1}...")

        if is_sequence_command:
            self.current_sequence_process = process
            self.update_sequence_navigation_buttons()
        process.start("bash", ["-c", command_text])
        self.statusBar().showMessage(f"Executing '{command_name}' in Slot {slot_idx+1}...")

    def read_output(self, process, slot_idx, execution_id):
        output = process.readAll().data().decode(errors='ignore')
        if output:
            self.output_boxes[slot_idx].append(output)

    def send_stdin(self):
        proc_id = self.current_stdin_process_id
        if proc_id and proc_id in self.running_processes:
            process = self.running_processes[proc_id]
            input_text = self.stdin_input.text() + "\n"
            process.write(input_text.encode())
            stdin_color = "#98fb98" if self.current_theme_name != "Light Theme" else "#28a745"
            idx = self.get_slot_index_for_execution_id(proc_id)
            if idx is not None:
                self.output_boxes[idx].append(f"<span style='color: {stdin_color};'>[IN] {input_text.strip()}</span>")
            self.stdin_input.clear()

    def process_finished(self, process, execution_id, is_sequence_command, slot_idx):
        status = "finished" if process.exitStatus() == QProcess.NormalExit else "crashed"
        color = "#28a745" if status == "finished" else "#dc3545"
        if self.current_theme_name != "Light Theme":
            color = "#90ee90" if status == "finished" else "#ff4500"
        self.timers[slot_idx].stop()
        duration = self.timer_counters[slot_idx]
        mins = int(duration // 60)
        secs = int(duration % 60)
        hunds = int((duration - int(duration)) * 100)
        self.output_boxes[slot_idx].append(
            f"<span style='color: {color};'>--- Process '{execution_id}' {status} (Duration: {mins:02d}:{secs:02d}.{hunds:02d}) ---</span>")
        self.running_processes.pop(execution_id, None)
        self.process_slots[slot_idx] = None
        self.process_exec_ids[slot_idx] = None
        self.timer_labels[slot_idx].setText("Timer: 00:00.00")
        self.timer_counters[slot_idx] = 0.0
        # Reset stdin if this one was it
        if execution_id == self.current_stdin_process_id:
            self.current_stdin_process_id = None
            self.stdin_input.setEnabled(False)
            self.stdin_input.setPlaceholderText("Stdin input for slot 1...")

        if is_sequence_command:
            self.current_sequence_process = None
            self.update_sequence_navigation_buttons()
            self.statusBar().showMessage("Sequence command finished. Ready for next step.")

        # Launch next from queue, if any
        while self.command_queue and self.get_free_slot_index() is not None:
            cmd, name, seq, queued_id = self.command_queue.popleft()
            self.execute_command(cmd, name, seq, None, queued_id)

        if not self.running_processes:
            self.statusBar().showMessage("Ready")

    # --------- STOP ALL -----------
    def stop_all_commands(self, confirm=True):
        if not self.running_processes:
            return
        if confirm:
            dialog = ConfirmDialog(self, "Confirm Stop All", "Stop all running commands?")
            if dialog.exec_() != QMessageBox.Yes:
                return
        for process in list(self.running_processes.values()):
            process.kill()
        self.running_processes.clear()
        self.clear_all_outputs()
        self.statusBar().showMessage("All commands stopped.")
        # Also stop any pending queue
        self.command_queue.clear()
        self.current_sequence_process = None
        self.current_stdin_process_id = None

    def closeEvent(self, event):
        self.stop_all_commands(confirm=False)
        event.accept()

    # ----------------- COMMAND MANAGEMENT (unchanged, but supports multiple outputs) -----------------
    def load_commands(self):
        self.command_list.clear()
        for cmd_id, name, command_text in self.db_manager.get_commands():
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, (cmd_id, command_text))
            self.command_list.addItem(item)
        self.update_button.setEnabled(False)
        self.delete_button.setEnabled(False)

    def load_selected_command(self, item):
        cmd_id, command_text = item.data(Qt.UserRole)
        self.command_name_input.setText(item.text())
        self.command_text_input.setText(command_text)
        self.selected_command_id = cmd_id
        self.update_button.setEnabled(True)
        self.delete_button.setEnabled(True)

    def save_command(self):
        name = self.command_name_input.text().strip()
        command_text = self.command_text_input.text().strip()
        if not name or not command_text:
            QMessageBox.warning(self, "Input Error", "Command name and text cannot be empty.")
            return
        if self.db_manager.add_command(name, command_text):
            self.statusBar().showMessage(f"Command '{name}' saved.")
            self.command_name_input.clear()
            self.command_text_input.clear()
            self.load_commands()
        else:
            QMessageBox.warning(self, "Save Error", f"Command name '{name}' already exists.")

    def update_command(self):
        if not hasattr(self, 'selected_command_id'):
            return
        new_name = self.command_name_input.text().strip()
        new_command_text = self.command_text_input.text().strip()
        if not new_name or not new_command_text:
            QMessageBox.warning(self, "Input Error", "Command name and text cannot be empty.")
            return
        if self.db_manager.update_command(self.selected_command_id, new_name, new_command_text):
            self.statusBar().showMessage(f"Command '{new_name}' updated.")
            self.command_name_input.clear()
            self.command_text_input.clear()
            self.load_commands()
        else:
            QMessageBox.warning(self, "Update Error", f"Command name '{new_name}' already exists.")

    def delete_command(self):
        if not hasattr(self, 'selected_command_id'):
            return
        dialog = ConfirmDialog(self, "Confirm Delete", f"Delete '{self.command_name_input.text()}'?")
        if dialog.exec_() == QMessageBox.Yes:
            if self.db_manager.delete_command(self.selected_command_id):
                self.statusBar().showMessage("Command deleted.")
                self.command_name_input.clear()
                self.command_text_input.clear()
                self.load_commands()

    def delete_all_commands(self):
        dialog = ConfirmDialog(self, "Confirm Delete All", "Are you sure you want to delete ALL saved single commands? This action cannot be undone.")
        if dialog.exec_() == QMessageBox.Yes:
            self.db_manager.delete_all_commands()
            self.statusBar().showMessage("All single commands have been deleted.")
            self.load_commands()

    # ---------------- SEQUENCE MANAGEMENT -------------------
    def load_sequences(self):
        self.sequence_list.clear()
        for seq_id, name, data in self.db_manager.get_sequences():
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, (seq_id, data))
            self.sequence_list.addItem(item)
        self.edit_sequence_button.setEnabled(False)
        self.delete_sequence_button.setEnabled(False)
        self.execute_sequence_button.setEnabled(False)

    def create_sequence(self):
        dialog = CreateSequenceDialog(self.db_manager, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            name, data = dialog.get_sequence_data()
            if name and data:
                if self.db_manager.add_sequence(name, data):
                    self.statusBar().showMessage(f"Sequence '{name}' saved.")
                    self.load_sequences()
                else:
                    QMessageBox.warning(self, "Save Error", f"Sequence name '{name}' already exists.")

    def edit_sequence(self):
        item = self.sequence_list.currentItem()
        if not item:
            return
        seq_id, data = item.data(Qt.UserRole)
        dialog = CreateSequenceDialog(self.db_manager, (seq_id, item.text(), data), self)
        if dialog.exec_() == QDialog.Accepted:
            name, new_data = dialog.get_sequence_data()
            if name and new_data and self.db_manager.update_sequence(seq_id, name, new_data):
                self.statusBar().showMessage(f"Sequence '{name}' updated.")
                self.load_sequences()

    def delete_sequence(self):
        item = self.sequence_list.currentItem()
        if not item:
            return
        dialog = ConfirmDialog(self, "Confirm Delete", f"Delete sequence '{item.text()}'?")
        if dialog.exec_() == QMessageBox.Yes:
            seq_id, _ = item.data(Qt.UserRole)
            if self.db_manager.delete_sequence(seq_id):
                self.statusBar().showMessage(f"Sequence '{item.text()}' deleted.")
                self.load_sequences()

    def load_selected_sequence_for_execution(self, item):
        self.edit_sequence_button.setEnabled(True)
        self.delete_sequence_button.setEnabled(True)
        self.execute_sequence_button.setEnabled(True)

    # --------- SEQUENCE EXECUTION (using parallel slots) ------
    def execute_selected_sequence(self):
        item = self.sequence_list.currentItem()
        if not item:
            return
        self.active_sequence_commands = item.data(Qt.UserRole)[1]
        if not self.active_sequence_commands:
            QMessageBox.warning(self, "Empty Sequence", "This sequence has no commands.")
            return
        self.sequence_execution_mode = True
        self.current_sequence_index = -1
        self.current_sequence_label.setText(f"Active Sequence: {item.text()}")
        self.current_command_label.setText("Current Command: -")
        self.sequence_control_group.setVisible(True)
        self.jump_to_combo_box.blockSignals(True)
        self.jump_to_combo_box.clear()
        for i, cmd_info in enumerate(self.active_sequence_commands):
            self.jump_to_combo_box.addItem(f"{i+1}. {cmd_info['name']}", i)
        self.jump_to_combo_box.blockSignals(False)
        self.update_sequence_navigation_buttons()
        exec_color = "#ffd700" if self.current_theme_name != "Light Theme" else "#ffc107"
        self.output_boxes[0].append(f"<span style='color: {exec_color};'>--- Starting Sequence: {item.text()}. Press 'Next' to begin. ---</span>")

    def run_next_command_in_sequence(self):
        if self.current_sequence_process and self.current_sequence_process.state() == QProcess.Running:
            return
        if self.current_sequence_index < len(self.active_sequence_commands) - 1:
            self.current_sequence_index += 1
            self.execute_current_sequence_step()
        else:
            self.statusBar().showMessage("End of sequence reached.")

    def run_previous_command_in_sequence(self):
        if self.current_sequence_process and self.current_sequence_process.state() == QProcess.Running:
            return
        if self.current_sequence_index > 0:
            self.current_sequence_index -= 1
            self.execute_current_sequence_step()

    def jump_to_command_in_sequence(self, index):
        if not self.sequence_execution_mode or index < 0 or (self.current_sequence_process and self.current_sequence_process.state() == QProcess.Running):
            return
        selected_index = self.jump_to_combo_box.itemData(index)
        if selected_index is not None:
            self.current_sequence_index = selected_index
            self.execute_current_sequence_step()

    def execute_current_sequence_step(self):
        cmd_info = self.active_sequence_commands[self.current_sequence_index]
        self.current_command_label.setText(f"Current: {cmd_info['name']} ({self.current_sequence_index + 1}/{len(self.active_sequence_commands)})")
        self.execute_command(cmd_info['command'], cmd_info['name'], is_sequence_command=True)

    def stop_current_sequence_execution(self, silent=False):
        if self.current_sequence_process:
            self.current_sequence_process.kill()
            self.current_sequence_process = None
        if self.sequence_execution_mode:
            if not silent:
                terminate_color = "#ff8c00" if self.current_theme_name != "Light Theme" else "#dc3545"
                self.output_boxes[0].append(f"<span style='color: {terminate_color};'>--- Sequence Stopped ---</span>")
            self.sequence_execution_mode = False
            self.sequence_control_group.setVisible(False)
            self.statusBar().showMessage("Ready")

    def update_sequence_navigation_buttons(self):
        if not self.sequence_execution_mode:
            return
        is_running = self.current_sequence_process and self.current_sequence_process.state() == QProcess.Running
        self.previous_command_button.setEnabled(self.current_sequence_index > 0 and not is_running)
        self.next_command_button.setEnabled(self.current_sequence_index < len(self.active_sequence_commands) - 1 and not is_running)
        self.jump_to_combo_box.setEnabled(not is_running)
        self.jump_to_combo_box.blockSignals(True)
        if self.current_sequence_index != self.jump_to_combo_box.currentIndex():
            self.jump_to_combo_box.setCurrentIndex(self.current_sequence_index)
        self.jump_to_combo_box.blockSignals(False)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = CommandExecutorApp()
    ex.show()
    sys.exit(app.exec_())
