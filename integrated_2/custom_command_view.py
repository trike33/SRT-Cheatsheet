import sys
import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QTextEdit, QPushButton, 
    QLabel, QComboBox, QGroupBox
)
from PyQt5.QtCore import QProcess, QTimer, Qt
from PyQt5.QtGui import QFont

class CustomCommandWidget(QWidget):
    """
    A widget that provides a 4-slot parallel terminal for running custom commands.
    """
    def __init__(self, working_directory, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.num_slots = 4
        self.processes = [None] * self.num_slots
        self.output_boxes = []
        self.timer_labels = []
        self.timers = []
        self.timer_counters = [0.0] * self.num_slots
        main_layout = QVBoxLayout(self)
        output_group = QGroupBox("Parallel Command Slots")
        slots_layout = QHBoxLayout(output_group)
        for i in range(self.num_slots):
            slot_layout = QVBoxLayout()
            timer_lbl = QLabel(f"Timer: 00:00.00")
            self.timer_labels.append(timer_lbl)
            output_box = QTextEdit()
            output_box.setReadOnly(True)
            output_box.setFont(QFont("Courier", 10))
            self.output_boxes.append(output_box)
            timer = QTimer(self)
            timer.setInterval(100)
            timer.timeout.connect(lambda idx=i: self.update_timer(idx))
            self.timers.append(timer)
            slot_layout.addWidget(QLabel(f"Slot {i + 1}"))
            slot_layout.addWidget(timer_lbl)
            slot_layout.addWidget(output_box)
            slots_layout.addLayout(slot_layout)
        main_layout.addWidget(output_group)
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target Slot:"))
        self.slot_selector = QComboBox()
        self.slot_selector.addItems([f"Slot {i+1}" for i in range(self.num_slots)])
        input_layout.addWidget(self.slot_selector)
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command and press Enter...")
        self.command_input.returnPressed.connect(self.run_command)
        input_layout.addWidget(self.command_input, 1)
        self.stop_all_button = QPushButton("Stop All")
        self.stop_all_button.clicked.connect(self.stop_all_commands)
        input_layout.addWidget(self.stop_all_button)
        main_layout.addLayout(input_layout)

    def update_timer(self, index):
        self.timer_counters[index] += 0.1
        total = self.timer_counters[index]
        mins = int(total // 60)
        secs = int(total % 60)
        hunds = int((total - int(total)) * 100)
        self.timer_labels[index].setText(f"Timer: {mins:02d}:{secs:02d}.{hunds:02d}")

    def run_command(self):
        slot_index = self.slot_selector.currentIndex()
        command = self.command_input.text().strip()
        if not command: return
        if self.processes[slot_index] and self.processes[slot_index].state() == QProcess.Running:
            self.processes[slot_index].write((command + "\n").encode())
            self.output_boxes[slot_index].append(f"<span style='color: lightgreen;'>&gt; {command}</span>")
        else:
            self.output_boxes[slot_index].clear()
            self.timer_counters[slot_index] = 0.0
            self.timers[slot_index].start()
            self.process = QProcess(self)
            self.process.setProcessChannelMode(QProcess.MergedChannels)
            self.process.setWorkingDirectory(self.working_directory)
            self.process.readyReadStandardOutput.connect(lambda idx=slot_index: self.handle_output(idx))
            self.process.finished.connect(lambda idx=slot_index: self.handle_finish(idx))
            self.processes[slot_index] = self.process
            self.output_boxes[slot_index].append(f"<span style='color: yellow;'>$ {command}</span>")
            if sys.platform == "win32": self.process.start('cmd.exe', ['/c', command])
            else: self.process.start('bash', ['-c', command])
        self.command_input.clear()

    def handle_output(self, index):
        if self.processes[index]:
            data = self.processes[index].readAllStandardOutput().data().decode(errors='ignore')
            self.output_boxes[index].insertPlainText(data)
            self.output_boxes[index].verticalScrollBar().setValue(self.output_boxes[index].verticalScrollBar().maximum())

    def handle_finish(self, index):
        self.timers[index].stop()
        self.output_boxes[index].append("<span style='color: orange;'>--- Process Finished ---</span>")
        self.processes[index] = None

    def stop_all_commands(self):
        for i, process in enumerate(self.processes):
            if process and process.state() == QProcess.Running:
                process.terminate()
                # This was the missing part:
                self.timers[i].stop()
                self.output_boxes[i].append("<span style='color: red;'>--- Process Terminated ---</span>")

    def stop_all_processes(self):
        self.stop_all_commands()
