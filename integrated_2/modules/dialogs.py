from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QDialogButtonBox, QLineEdit,
    QCheckBox, QSpinBox, QMessageBox, QInputDialog, QLabel,
    QTextEdit, QFileDialog, QSplitter, QHeaderView, QTabWidget
)
from PyQt5.QtCore import Qt
from utils import db as command_db
import os
from PyQt5.QtGui import QFont

class TemplateEditDialog(QDialog):
    """A dialog for adding/editing a structured report template."""
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Report Template")
        self.setGeometry(250, 250, 600, 500)
        
        layout = QVBoxLayout(self)
        self.category_input = QLineEdit(data['category'] if data else "")
        self.category_input.setPlaceholderText("Vulnerability Category (e.g., SQL Injection)")
        
        self.tabs = QTabWidget()
        self.desc_input = QTextEdit(data.get('description', '') if data else "")
        self.impact_input = QTextEdit(data.get('impact', '') if data else "")
        self.validation_input = QTextEdit(data.get('validation_steps', '') if data else "")
        self.fix_input = QTextEdit(data.get('fix_recommendation', '') if data else "")

        self.tabs.addTab(self.desc_input, "Description")
        self.tabs.addTab(self.impact_input, "Impact")
        self.tabs.addTab(self.validation_input, "Validation Steps")
        self.tabs.addTab(self.fix_input, "Recommended Fix")

        layout.addWidget(QLabel("Category:"))
        layout.addWidget(self.category_input)
        layout.addWidget(self.tabs)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def get_data(self):
        return {
            'category': self.category_input.text(),
            'description': self.desc_input.toPlainText(),
            'impact': self.impact_input.toPlainText(),
            'validation': self.validation_input.toPlainText(),
            'fix': self.fix_input.toPlainText()
        }

class TemplateEditorDialog(QDialog):
    """A dialog for managing all report templates with a better view."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Report Template Manager")
        self.setGeometry(200, 200, 900, 600)
        
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)
        
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["ID", "Category"])
        self.table.setColumnHidden(0, True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        self.template_preview = QTextEdit(readOnly=True)
        self.template_preview.setFont(QFont("Courier New"))
        
        splitter.addWidget(self.table)
        splitter.addWidget(self.template_preview)
        splitter.setSizes([300, 600])
        layout.addWidget(splitter)
        
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add")
        edit_btn = QPushButton("Edit")
        delete_btn = QPushButton("Delete")
        button_layout.addStretch()
        button_layout.addWidget(add_btn)
        button_layout.addWidget(edit_btn)
        button_layout.addWidget(delete_btn)
        layout.addLayout(button_layout)

        self.load_templates()
        
        self.table.itemSelectionChanged.connect(self.display_selected_template)
        add_btn.clicked.connect(self.add_row)
        edit_btn.clicked.connect(self.edit_row)
        delete_btn.clicked.connect(self.delete_row)

    def load_templates(self):
        self.table.setRowCount(0)
        self.templates_data = command_db.get_all_templates() # Store all data
        for tpl in self.templates_data:
            row_pos = self.table.rowCount()
            self.table.insertRow(row_pos)
            self.table.setItem(row_pos, 0, QTableWidgetItem(str(tpl['id'])))
            self.table.setItem(row_pos, 1, QTableWidgetItem(tpl['category']))

    def display_selected_template(self):
        selected_row = self.table.currentRow()
        if selected_row < 0: return

        template = self.templates_data[selected_row]
        preview_text = f"""
### Description ###
{template.get('description', '')}

### Impact ###
{template.get('impact', '')}

### Validation Steps ###
{template.get('validation_steps', '')}

### Recommended Fix ###
{template.get('fix_recommendation', '')}
        """
        self.template_preview.setPlainText(preview_text)

    def add_row(self):
        dialog = TemplateEditDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            command_db.add_template(data['category'], data['description'], data['impact'], data['validation'], data['fix'])
            self.load_templates()

    def edit_row(self):
        selected_row = self.table.currentRow()
        if selected_row < 0: return
        
        # --- FIX: Pass the full template dictionary to the edit dialog ---
        current_data = self.templates_data[selected_row]
        
        dialog = TemplateEditDialog(self, data=current_data)
        if dialog.exec_() == QDialog.Accepted:
            new_data = dialog.get_data()
            command_db.update_template(
                current_data['id'], new_data['category'], new_data['description'],
                new_data['impact'], new_data['validation'], new_data['fix']
            )
            self.load_templates()

    def delete_row(self):
        selected_row = self.table.currentRow()
        if selected_row < 0: return
        tpl_id = int(self.table.item(selected_row, 0).text())
        reply = QMessageBox.question(self, 'Confirm Deletion', 'Are you sure?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            command_db.delete_template(tpl_id)
            self.load_templates()

class DomainsFileDialog(QDialog):
    """A dialog for creating and editing a domains file."""
    def __init__(self, working_directory, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.setWindowTitle("Setup Domains File")
        self.setGeometry(200, 200, 400, 300)
        
        layout = QVBoxLayout(self)
        self.domains_text_edit = QTextEdit()
        self.domains_text_edit.setPlaceholderText("Enter one domain per line...")
        layout.addWidget(self.domains_text_edit)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_file)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def save_file(self):
        """Opens a file dialog to save the domain list."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Domains File", self.working_directory, "Text Files (*.txt)"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.domains_text_edit.toPlainText())
                self.accept()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not save file: {e}")

class CommandEditDialog(QDialog):
    """A dialog for adding or editing a single standard command."""
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Command")
        
        layout = QVBoxLayout(self)
        self.command_text = QLineEdit(data['text'] if data else "")
        self.execution_order = QSpinBox()
        self.execution_order.setRange(1, 999)
        self.execution_order.setValue(data['order'] if data else 1)
        self.use_shell = QCheckBox("Use Shell")
        self.use_shell.setChecked(data['shell'] if data else False)
        self.run_in_background = QCheckBox("Run in Background")
        self.run_in_background.setChecked(data['background'] if data else False)

        layout.addWidget(QLabel("Command:"))
        layout.addWidget(self.command_text)
        layout.addWidget(QLabel("Execution Order:"))
        layout.addWidget(self.execution_order)
        layout.addWidget(self.use_shell)
        layout.addWidget(self.run_in_background)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def get_data(self):
        return {
            'text': self.command_text.text(),
            'shell': self.use_shell.isChecked(),
            'background': self.run_in_background.isChecked(),
            'order': self.execution_order.value()
        }

class CommandEditorDialog(QDialog):
    """The main editor dialog for managing the standard command sequence."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Command Sequence Editor")
        self.setGeometry(150, 150, 800, 600)
        
        layout = QVBoxLayout(self)
        
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Command", "Use Shell", "Run in BG", "Order"])
        self.table.setColumnHidden(0, True)
        layout.addWidget(self.table)
        
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add")
        edit_btn = QPushButton("Edit")
        delete_btn = QPushButton("Delete")
        button_layout.addWidget(add_btn)
        button_layout.addWidget(edit_btn)
        button_layout.addWidget(delete_btn)
        layout.addLayout(button_layout)

        self.load_commands()
        
        add_btn.clicked.connect(self.add_row)
        edit_btn.clicked.connect(self.edit_row)
        delete_btn.clicked.connect(self.delete_row)

    def load_commands(self):
        self.table.setRowCount(0)
        commands = command_db.get_all_commands()
        for cmd in commands:
            row_pos = self.table.rowCount()
            self.table.insertRow(row_pos)
            self.table.setItem(row_pos, 0, QTableWidgetItem(str(cmd['id'])))
            self.table.setItem(row_pos, 1, QTableWidgetItem(cmd['command_text']))
            
            shell_check = QCheckBox()
            shell_check.setChecked(bool(cmd['use_shell']))
            shell_check.setEnabled(False)
            self.table.setCellWidget(row_pos, 2, shell_check)
            
            bg_check = QCheckBox()
            bg_check.setChecked(bool(cmd['run_in_background']))
            bg_check.setEnabled(False)
            self.table.setCellWidget(row_pos, 3, bg_check)
            
            self.table.setItem(row_pos, 4, QTableWidgetItem(str(cmd['execution_order'])))

    def add_row(self):
        dialog = CommandEditDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            command_db.add_command(data['text'], data['shell'], data['background'])
            self.load_commands()

    def edit_row(self):
        selected_row = self.table.currentRow()
        if selected_row < 0: return
        cmd_id = int(self.table.item(selected_row, 0).text())
        current_data = {
            'text': self.table.item(selected_row, 1).text(),
            'shell': self.table.cellWidget(selected_row, 2).isChecked(),
            'background': self.table.cellWidget(selected_row, 3).isChecked(),
            'order': int(self.table.item(selected_row, 4).text())
        }
        dialog = CommandEditDialog(self, data=current_data)
        if dialog.exec_() == QDialog.Accepted:
            new_data = dialog.get_data()
            command_db.update_command(cmd_id, new_data['text'], new_data['shell'], new_data['order'], new_data['background'])
            self.load_commands()

    def delete_row(self):
        selected_row = self.table.currentRow()
        if selected_row < 0: return
        cmd_id = int(self.table.item(selected_row, 0).text())
        reply = QMessageBox.question(self, 'Confirm Deletion', 'Are you sure?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            command_db.delete_command(cmd_id)
            self.load_commands()

class SudoCommandEditorDialog(QDialog):
    """A dialog for adding/deleting commands in the sudo_commands table."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sudo Command Manager")
        self.setGeometry(200, 200, 700, 400)
        
        layout = QVBoxLayout(self)
        
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["ID", "Command"])
        self.table.setColumnHidden(0, True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add")
        delete_btn = QPushButton("Delete")
        button_layout.addStretch()
        button_layout.addWidget(add_btn)
        button_layout.addWidget(delete_btn)
        layout.addLayout(button_layout)

        self.load_commands()
        
        add_btn.clicked.connect(self.add_command)
        delete_btn.clicked.connect(self.delete_command)

    def load_commands(self):
        self.table.setRowCount(0)
        commands = command_db.get_all_sudo_commands()
        for cmd in commands:
            row_pos = self.table.rowCount()
            self.table.insertRow(row_pos)
            self.table.setItem(row_pos, 0, QTableWidgetItem(str(cmd['id'])))
            self.table.setItem(row_pos, 1, QTableWidgetItem(cmd['command_text']))

    def add_command(self):
        text, ok = QInputDialog.getText(self, 'Add Sudo Command', 'Enter the new command:')
        if ok and text:
            if not text.strip().startswith('sudo'):
                text = f"sudo {text.strip()}"
            command_db.add_sudo_command(text)
            self.load_commands()

    def delete_command(self):
        selected_row = self.table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Selection Error", "Please select a command to delete.")
            return

        cmd_id = int(self.table.item(selected_row, 0).text())
        reply = QMessageBox.question(self, 'Confirm Deletion', 'Are you sure?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            command_db.delete_sudo_command(cmd_id)
            self.load_commands()