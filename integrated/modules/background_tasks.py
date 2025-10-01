from PyQt5.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout, QListWidgetItem, QMessageBox
from PyQt5.QtCore import Qt, pyqtSignal

class BackgroundTasksDialog(QDialog):
    """A dialog window to display and manage background tasks."""
    task_termination_requested = pyqtSignal(int) # Emits the PID to terminate

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Background Tasks")
        self.setGeometry(200, 200, 500, 400)
        
        main_layout = QVBoxLayout(self)
        self.bg_tasks_list = QListWidget()
        main_layout.addWidget(self.bg_tasks_list)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        terminate_btn = QPushButton("Terminate Selected Task")
        terminate_btn.clicked.connect(self.terminate_selected_task)
        button_layout.addWidget(terminate_btn)
        main_layout.addLayout(button_layout)

    def add_background_task(self, pid, command):
        item = QListWidgetItem(f"[PID: {pid}] {command}")
        item.setData(Qt.UserRole, pid)
        self.bg_tasks_list.addItem(item)

    def remove_background_task(self, pid):
        for i in range(self.bg_tasks_list.count()):
            item = self.bg_tasks_list.item(i)
            if item and item.data(Qt.UserRole) == pid:
                self.bg_tasks_list.takeItem(i)
                break

    def terminate_selected_task(self):
        selected_items = self.bg_tasks_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a background task to terminate.")
            return
        item = selected_items[0]
        pid = item.data(Qt.UserRole)
        self.task_termination_requested.emit(pid)
