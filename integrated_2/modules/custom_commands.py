import os
import shlex
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QFrame, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QLabel
from PyQt5.QtCore import QProcess, QTimer, Qt, QSize
from PyQt5.QtGui import QFont, QIcon

class CustomCommandsWidget(QWidget):
    """
    A widget that provides multiple terminal-like slots for running custom commands.
    """
    def __init__(self, working_directory, icon_path, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.icon_path = icon_path
        self.processes = {}
        self.timers = {}
        self.num_slots = 4
        self.slots = []  # To hold references to each slot's widgets

        # --- Load Icons ---
        self.running_icon = QIcon(os.path.join(self.icon_path, "run.svg"))
        self.stopped_icon = QIcon(os.path.join(self.icon_path, "stop.svg"))

        main_layout = QVBoxLayout(self)

        # "Stop All" button
        stop_all_layout = QHBoxLayout()
        stop_all_layout.addStretch()
        stop_all_button = QPushButton("Stop All Running Commands")
        stop_all_button.clicked.connect(self.stop_all_processes)
        stop_all_layout.addWidget(stop_all_button)
        main_layout.addLayout(stop_all_layout)

        # Create and connect each terminal slot
        for i in range(self.num_slots):
            slot_widgets = self.create_terminal_slot()
            self.slots.append(slot_widgets)
            main_layout.addWidget(slot_widgets['frame'])
            
            # Connect signals using direct references
            slot_widgets['input'].returnPressed.connect(lambda idx=i: self.start_process(idx))
            slot_widgets['start_btn'].clicked.connect(lambda idx=i: self.start_process(idx))
            slot_widgets['stop_btn'].clicked.connect(lambda idx=i: self.stop_process(idx))

    def create_terminal_slot(self):
        """Creates widgets for a single slot and returns them in a dictionary."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        layout = QVBoxLayout(frame)

        output_display = QTextEdit(readOnly=True)
        output_display.setFont(QFont("Courier", 10))
        layout.addWidget(output_display)

        timer_label = QLabel("Elapsed: 00:00:00")
        timer_label.setAlignment(Qt.AlignRight)

        input_layout = QHBoxLayout()
        status_icon_label = QLabel()
        status_icon_label.setPixmap(self.stopped_icon.pixmap(QSize(16, 16)))
        input_layout.addWidget(status_icon_label)
        
        command_input = QLineEdit()
        command_input.setPlaceholderText("Enter command and press Enter")
        
        start_button = QPushButton("Run")
        stop_button = QPushButton("Stop")
        stop_button.setEnabled(False)

        input_layout.addWidget(command_input)
        input_layout.addWidget(start_button)
        input_layout.addWidget(stop_button)
        
        bottom_layout = QHBoxLayout()
        bottom_layout.addLayout(input_layout, 4)
        bottom_layout.addWidget(timer_label, 1)
        layout.addLayout(bottom_layout)

        return {
            'frame': frame, 'output': output_display, 'input': command_input,
            'start_btn': start_button, 'stop_btn': stop_button,
            'timer_lbl': timer_label, 'status_icon': status_icon_label
        }

    def start_process(self, index):
        """Starts a new process using direct widget references."""
        if index in self.processes and self.processes[index]['process'].state() == QProcess.Running:
            return

        slot = self.slots[index]
        command_input = slot['input']
        command_text = command_input.text()
        if not command_text:
            return

        slot['output'].clear()
        
        process = QProcess()
        self.processes[index] = {'process': process, 'elapsed_time': 0}
        
        process.setProcessChannelMode(QProcess.MergedChannels)
        process.readyReadStandardOutput.connect(lambda: self.handle_output(index))
        process.finished.connect(lambda: self.handle_finish(index))
        
        self.timers[index] = QTimer()
        self.timers[index].timeout.connect(lambda: self.update_timer(index))
        self.timers[index].start(1000)

        process.start(shlex.split(command_text)[0], shlex.split(command_text)[1:])
        process.setWorkingDirectory(self.working_directory)
        self.update_ui_for_start(index)
    
    def stop_process(self, index):
        if index in self.processes and self.processes[index]['process'].state() == QProcess.Running:
            self.processes[index]['process'].kill()

    def handle_output(self, index):
        process = self.processes[index]['process']
        output = process.readAllStandardOutput().data().decode(errors='ignore')
        self.slots[index]['output'].append(output)

    def handle_finish(self, index):
        if index in self.timers:
            self.timers[index].stop()
        self.update_ui_for_finish(index)
        
    def stop_all_processes(self):
        for i, process_info in list(self.processes.items()):
            process = process_info['process']
            if process.state() == QProcess.Running:
                process.blockSignals(True)
                process.kill()
                process.waitForFinished(1000)
                process.blockSignals(False)
                
                if i in self.timers:
                    self.timers[i].stop()
                self.update_ui_for_finish(i)

    def update_timer(self, index):
        if index in self.processes:
            self.processes[index]['elapsed_time'] += 1
            elapsed = self.processes[index]['elapsed_time']
            hours, rem = divmod(elapsed, 3600)
            minutes, seconds = divmod(rem, 60)
            self.slots[index]['timer_lbl'].setText(f"Elapsed: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")

    def update_ui_for_start(self, index):
        slot = self.slots[index]
        slot['start_btn'].setEnabled(False)
        slot['stop_btn'].setEnabled(True)
        slot['input'].setEnabled(False)
        slot['status_icon'].setPixmap(self.running_icon.pixmap(QSize(16, 16)))

    def update_ui_for_finish(self, index):
        if index < len(self.slots):
            slot = self.slots[index]
            slot['start_btn'].setEnabled(True)
            slot['stop_btn'].setEnabled(False)
            slot['input'].setEnabled(True)
            slot['status_icon'].setPixmap(self.stopped_icon.pixmap(QSize(16, 16)))
            # Reset the timer label's text
            slot['timer_lbl'].setText("Elapsed: 00:00:00")
            
        if index in self.processes:
            del self.processes[index]
        if index in self.timers:
            del self.timers[index]
            
    def set_working_directory(self, path):
        self.working_directory = path