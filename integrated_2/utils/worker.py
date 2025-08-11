import os
import shlex
import subprocess
import argparse
from PyQt5.QtCore import QThread, pyqtSignal
from utils import db as command_db
from utils import recon_tools

class Worker(QThread):
    """Worker thread to run the reconnaissance commands."""
    progress = pyqtSignal(str)
    progress_updated = pyqtSignal(int, int)
    scan_updated = pyqtSignal()
    background_task_started = pyqtSignal(int, str)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target_name, scope_file, working_directory):
        super().__init__()
        self.target_name = target_name
        self.scope_file = scope_file
        self.working_directory = working_directory
        self.is_running = True
        self.output_dir = os.path.join(self.working_directory, self.target_name)
        self.background_processes = {}

    def stop(self):
        self.is_running = False
        self.progress.emit("[!] Scan cancellation requested. Finishing current command...")

    def run_background_command(self, command_text):
        try:
            proc = subprocess.Popen(command_text, shell=True, cwd=self.output_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.background_processes[proc.pid] = proc
            self.background_task_started.emit(proc.pid, command_text)
            self.progress.emit(f"[BG] Started background task (PID: {proc.pid}): {command_text}")
        except Exception as e:
            self.error.emit(f"Failed to start background process for command '{command_text}': {e}")

    def run_internal_command(self, command_text):
        parser = argparse.ArgumentParser()
        parser.add_argument('command')
        parser.add_argument('--input')
        parser.add_argument('--output')
        parser.add_argument('--subdomains')
        parser.add_argument('--scope')
        parser.add_argument('--scope_file')

        try:
            args = parser.parse_args(shlex.split(command_text.replace("internal:", "")))
            
            tool_map = {
                "run_ipparser": recon_tools.run_ipparser,
                "run_domain_extracter": recon_tools.run_domain_extracter,
                "run_domain_enum": recon_tools.run_domain_enum,
                "run_format_ips": recon_tools.run_format_ips,
                "run_reverse_dns": recon_tools.run_reverse_dns,
            }

            if args.command in tool_map:
                # Prepare arguments for the specific tool
                tool_args = {}
                if args.command == 'run_ipparser':
                    tool_args['scope_file_path'] = os.path.join(self.output_dir, args.input if args.input else self.scope_file)
                    tool_args['output_dir'] = self.output_dir
                elif args.command == 'run_domain_extracter':
                    tool_args['input_file_path'] = os.path.join(self.output_dir, args.input)
                    tool_args['output_file_path'] = os.path.join(self.output_dir, args.output)
                elif args.command == 'run_domain_enum':
                    tool_args['subdomains_file_path'] = os.path.join(self.output_dir, args.subdomains)
                    tool_args['scope_file_path'] = os.path.join(self.output_dir, args.scope)
                    tool_args['output_file_path'] = os.path.join(self.output_dir, args.output)
                elif args.command == 'run_format_ips':
                    tool_args['input_file_path'] = os.path.join(self.output_dir, args.input)
                    if args.output:
                        tool_args['output_file_path'] = os.path.join(self.output_dir, args.output)
                elif args.command == 'run_reverse_dns':
                    tool_args['input_file_path'] = os.path.join(self.output_dir, args.input)
                    tool_args['output_file_path'] = os.path.join(self.output_dir, args.output)

                success, message = tool_map[args.command](**tool_args)

                self.progress.emit(f"[{args.command}] {message}")
                if success and (args.command == 'run_ipparser' or 'domain' in args.command):
                    self.scan_updated.emit()
            else:
                self.error.emit(f"Unknown internal command: {args.command}")

        except Exception as e:
            self.error.emit(f"Error processing internal command '{command_text}': {e}")


    def run_external_command(self, command_text, use_shell):
        try:
            proc = subprocess.Popen(
                command_text if use_shell else shlex.split(command_text),
                shell=use_shell,
                cwd=self.output_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in iter(proc.stdout.readline, ''):
                if not self.is_running:
                    proc.terminate()
                    break
                self.progress.emit(line.strip())
            proc.stdout.close()
            proc.wait()
        except FileNotFoundError:
            self.error.emit(f"Command not found: {shlex.split(command_text)[0]}")
        except Exception as e:
            self.error.emit(f"Error executing '{command_text}': {e}")
    
    def run(self):
        commands = command_db.get_all_commands()
        total_commands = len(commands)

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Initial IP Parser run
        self.progress.emit("[*] Starting with IP parsing...")
        self.run_internal_command(f"internal:run_ipparser --input {self.scope_file} --output scopeips")

        for i, cmd_row in enumerate(commands):
            if not self.is_running:
                break
            
            command_text = cmd_row['command_text'].format(
    target_name=self.target_name, 
    scope_file=self.scope_file
)
            
            self.progress.emit(f"\n<span style='color: #007acc;'>--- Running Step {i+1}/{total_commands}: {command_text} ---</span>")
            self.progress_updated.emit(i + 1, total_commands)
            
            if cmd_row['run_in_background']:
                self.run_background_command(command_text)
            elif command_text.startswith("internal:"):
                self.run_internal_command(command_text)
            else:
                self.run_external_command(command_text, cmd_row['use_shell'])
        
        self.finished.emit()