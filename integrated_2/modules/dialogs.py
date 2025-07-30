import os
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit, 
    QPushButton, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem, 
    QSpinBox, QCheckBox, QDialogButtonBox, QAbstractItemView
)
from PyQt5.QtCore import Qt
from utils import db as command_db

class DomainsFileDialog(QDialog):
    """A dialog to create, edit, and save a domains file."""
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
        self.button_box.button(QDialogButtonBox.Save).setText("Save and Close")
        self.button_box.accepted.connect(self.save_and_accept)
        self.button_box.rejected.connect(self.reject)
        button_layout.addWidget(self.button_box)
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
        self.table.setColumnWidth(1, 120); self.table.setColumnWidth(2, 450); self.table.setColumnWidth(3, 80); self.table.setColumnWidth(4, 80)
        layout.addWidget(self.table)
        button_layout = QHBoxLayout()
        add_btn, edit_btn, delete_btn = QPushButton("Add New"), QPushButton("Edit Selected"), QPushButton("Delete Selected")
        add_btn.clicked.connect(self.add_row); edit_btn.clicked.connect(self.edit_row); delete_btn.clicked.connect(self.delete_row)
        button_layout.addStretch(); button_layout.addWidget(add_btn); button_layout.addWidget(edit_btn); button_layout.addWidget(delete_btn)
        layout.addLayout(button_layout)
        self.load_commands()

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

