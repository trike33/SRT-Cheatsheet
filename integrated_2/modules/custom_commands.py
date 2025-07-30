import os
import re
import shlex
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QFrame, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QLabel
from PyQt5.QtCore import QProcess, QTimer, Qt
from PyQt5.QtGui import QFont

class CustomCommandsWidget(QWidget):
    """
    A widget that provides multiple terminal-like slots for running custom commands.
    """
    def __init__(self, working_directory, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.processes = {}  # Using a dictionary to manage processes per slot
        self.timers = {}
        self.num_slots = 4

        main_layout = QVBoxLayout(self)

        # "Stop All" button at the top
        stop_all_layout = QHBoxLayout()
        stop_all_layout.addStretch()
        stop_all_button = QPushButton("Stop All Running Commands")
        stop_all_button.clicked.connect(self.stop_all_processes)
        stop_all_layout.addWidget(stop_all_button)
        main_layout.addLayout(stop_all_layout)

        for i in range(self.num_slots):
            frame, layout = self.create_terminal_slot(i)
            main_layout.addWidget(frame)

    def create_terminal_slot(self, slot_index):
        """Creates a single terminal slot with its widgets and layouts."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(frame)

        # Output display
        output_display = QTextEdit(readOnly=True)
        output_display.setFont(QFont("Courier", 10))
        output_display.setObjectName(f"output_{slot_index}")
        layout.addWidget(output_display)

        # Timer label
        timer_label = QLabel("Elapsed: 00:00:00")
        timer_label.setObjectName(f"timer_label_{slot_index}")
        timer_label.setAlignment(Qt.AlignRight)

        # Input and buttons
        input_layout = QHBoxLayout()
        command_input = QLineEdit()
        command_input.setObjectName(f"input_{slot_index}")
        command_input.setPlaceholderText("Enter command and press Enter")
        command_input.returnPressed.connect(lambda idx=slot_index: self.start_process(idx))
        
        start_button = QPushButton("Run")
        start_button.setObjectName(f"start_button_{slot_index}")
        start_button.clicked.connect(lambda idx=slot_index: self.start_process(idx))
        
        stop_button = QPushButton("Stop")
        stop_button.setObjectName(f"stop_button_{slot_index}")
        stop_button.setEnabled(False)
        stop_button.clicked.connect(lambda idx=slot_index: self.stop_process(idx))

        input_layout.addWidget(command_input)
        input_layout.addWidget(start_button)
        input_layout.addWidget(stop_button)
        
        bottom_layout = QHBoxLayout()
        bottom_layout.addLayout(input_layout, 4)
        bottom_layout.addWidget(timer_label, 1)
        layout.addLayout(bottom_layout)

        return frame, layout

    def start_process(self, index):
        """Starts a new process in the specified terminal slot."""
        if index in self.processes and self.processes[index]['process'].state() == QProcess.Running:
            return

        command_input = self.findChild(QLineEdit, f"input_{index}")
        command_text = command_input.text()
        if not command_text:
            return

        output_display = self.findChild(QTextEdit, f"output_{index}")
        output_display.clear()
        
        process = QProcess()
        self.processes[index] = {'process': process, 'elapsed_time': 0}
        
        process.setProcessChannelMode(QProcess.MergedChannels)
        process.readyReadStandardOutput.connect(lambda idx=index: self.handle_output(idx))
        process.finished.connect(lambda idx=index: self.handle_finish(idx))
        
        # Setup and start the timer
        self.timers[index] = QTimer()
        self.timers[index].timeout.connect(lambda idx=index: self.update_timer(idx))
        self.timers[index].start(1000)

        process.start(shlex.split(command_text)[0], shlex.split(command_text)[1:])
        process.setWorkingDirectory(self.working_directory)
        self.update_ui_for_start(index)
    
    def stop_process(self, index):
        """Stops the process running in the specified slot."""
        if index in self.processes and self.processes[index]['process'].state() == QProcess.Running:
            self.processes[index]['process'].kill()

    def handle_output(self, index):
        """Appends new output from the process to its display."""
        process = self.processes[index]['process']
        output = process.readAllStandardOutput().data().decode(errors='ignore')
        output_display = self.findChild(QTextEdit, f"output_{index}")
        output_display.append(output)

    def handle_finish(self, index):
        """Cleans up after a process has finished."""
        if index in self.timers:
            self.timers[index].stop()
        self.update_ui_for_finish(index)
        
    def stop_all_processes(self):
        """Stops all currently running commands."""
        # Iterate over a copy of the items since the dictionary might change during the loop
        for i, process_info in list(self.processes.items()):
            process = process_info['process']
            if process.state() == QProcess.Running:
                # *** FIX: Block signals to prevent handle_finish from being called automatically ***
                process.blockSignals(True)
                process.kill()
                process.waitForFinished(1000) # Give it a moment to die
                process.blockSignals(False)
                
                # Manually stop the timer and update the UI
                if i in self.timers:
                    self.timers[i].stop()
                self.update_ui_for_finish(i)

    def update_timer(self, index):
        """Updates the elapsed time display for a running process."""
        if index in self.processes:
            self.processes[index]['elapsed_time'] += 1
            elapsed = self.processes[index]['elapsed_time']
            hours, rem = divmod(elapsed, 3600)
            minutes, seconds = divmod(rem, 60)
            timer_label = self.findChild(QLabel, f"timer_label_{index}")
            timer_label.setText(f"Elapsed: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")

    def update_ui_for_start(self, index):
        """Updates UI elements when a process starts."""
        self.findChild(QPushButton, f"start_button_{index}").setEnabled(False)
        self.findChild(QPushButton, f"stop_button_{index}").setEnabled(True)
        self.findChild(QLineEdit, f"input_{index}").setEnabled(False)

    def update_ui_for_finish(self, index):
        """Resets UI elements when a process finishes."""
        if self.findChild(QPushButton, f"start_button_{index}"):
            self.findChild(QPushButton, f"start_button_{index}").setEnabled(True)
            self.findChild(QPushButton, f"stop_button_{index}").setEnabled(False)
            self.findChild(QLineEdit, f"input_{index}").setEnabled(True)
        if index in self.processes:
            del self.processes[index]
        if index in self.timers:
            del self.timers[index]
            
    def set_working_directory(self, path):
        """Updates the working directory for new commands."""
        self.working_directory = path