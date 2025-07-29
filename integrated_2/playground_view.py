import re
import os
from collections import defaultdict
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QTreeWidget, QTreeWidgetItem, QLabel, QDialog, QSplitter, QListWidget, QListWidgetItem
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon

class HttpxResult:
    """A data class to hold parsed data from a single httpx output line."""
    def __init__(self, url, status_codes, content_length, title, technologies, redirect_url):
        self.url = url
        self.status_codes = status_codes
        self.content_length = content_length
        self.title = title
        self.technologies = technologies
        self.redirect_url = redirect_url
        self.final_status_code = status_codes[-1] if status_codes else 'N/A'
        self.num_redirects = len(status_codes) - 1 if len(status_codes) > 1 else 0

def parse_httpx_file(file_path):
    """Parses an httpx output file and returns a list of HttpxResult objects."""
    results = []
    line_regex = re.compile(
        r"^(?P<url>https?://[^\s]+)\s+"
        r"\[\s*(?P<status_codes>[\d\s,]+)\s*\]\s+"
        r"\[\s*(?P<content_length>\d+)\s*\]\s*"
        r"(?:\[\s*(?P<title>[^\]]+)\s*\]\s*)?"
        r"(?:\[\s*(?P<redirect_url>https?://[^\s]+)\s*\]\s*)?"
        r"(?:\[\s*(?P<technologies>[^\]]+)\s*\])?",
        re.IGNORECASE
    )
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = ansi_escape.sub('', line).strip()
                match = line_regex.match(line)
                if match:
                    data = match.groupdict()
                    status_codes = [int(s.strip()) for s in data.get('status_codes', '').split(',') if s.strip().isdigit()]
                    technologies = [t.strip() for t in data.get('technologies', '').split(',') if t.strip()] if data.get('technologies') else []
                    result = HttpxResult(
                        url=data.get('url', ''), status_codes=status_codes, content_length=int(data.get('content_length', 0)),
                        title=data.get('title', '').strip(), technologies=technologies, redirect_url=data.get('redirect_url', '').strip()
                    )
                    results.append(result)
    except Exception as e:
        print(f"Error parsing file {file_path}: {e}")
    return results

class PlaygroundWindow(QDialog):
    """A dedicated window for viewing and grouping results from a target folder."""
    def __init__(self, target_folder_path, file_icon, parent=None):
        super().__init__(parent)
        self.target_folder_path = target_folder_path
        self.file_icon = file_icon
        self.results = []
        
        self.setWindowTitle(f"Playground - {os.path.basename(target_folder_path)}")
        self.setGeometry(150, 150, 1000, 700)
        
        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)
        
        # --- Left side: File List ---
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.addWidget(QLabel("Output Files"))
        self.files_list = QListWidget()
        self.files_list.itemDoubleClicked.connect(self.load_file_from_list)
        left_layout.addWidget(self.files_list)
        splitter.addWidget(left_widget)

        # --- Right side: Analysis View ---
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Group By:"))
        self.grouping_combo = QComboBox()
        self.grouping_combo.addItems(["Final Status Code", "Technology", "Content Length", "Number of Redirects"])
        self.grouping_combo.currentTextChanged.connect(self.group_and_display_data)
        controls_layout.addWidget(self.grouping_combo)
        controls_layout.addStretch()
        right_layout.addLayout(controls_layout)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["URL", "Status", "Length", "Title", "Redirects"])
        self.tree.setColumnWidth(0, 350); self.tree.setColumnWidth(1, 100); self.tree.setColumnWidth(2, 100); self.tree.setColumnWidth(3, 200)
        right_layout.addWidget(self.tree)
        splitter.addWidget(right_widget)
        
        splitter.setSizes([200, 800])
        main_layout.addWidget(splitter)
        
        self.populate_files_list()

    def populate_files_list(self):
        """Scans the target directory and lists the files."""
        self.files_list.clear()
        try:
            for filename in sorted(os.listdir(self.target_folder_path)):
                self.files_list.addItem(QListWidgetItem(self.file_icon, filename))
        except OSError as e:
            print(f"Could not read directory {self.target_folder_path}: {e}")

    def load_file_from_list(self, item):
        """Loads the content of the double-clicked file."""
        file_path = os.path.join(self.target_folder_path, item.text())
        self.results = parse_httpx_file(file_path)
        self.group_and_display_data()

    def group_and_display_data(self):
        """Groups the loaded data based on the selected criteria and displays it."""
        if not self.results: self.tree.clear(); return
        group_by = self.grouping_combo.currentText()
        grouped_data = defaultdict(list)
        for res in self.results:
            if group_by == "Final Status Code": grouped_data[res.final_status_code].append(res)
            elif group_by == "Content Length":
                if res.content_length == 0: key = "0 bytes"
                elif res.content_length < 1024: key = "1-1023 bytes"
                elif res.content_length < 10240: key = "1-10 KB"
                else: key = "> 10 KB"
                grouped_data[key].append(res)
            elif group_by == "Number of Redirects": grouped_data[res.num_redirects].append(res)
            elif group_by == "Technology":
                if res.technologies:
                    for tech in res.technologies: grouped_data[tech].append(res)
                else: grouped_data["(No Technology Detected)"].append(res)
        self.display_in_tree(grouped_data)

    def display_in_tree(self, grouped_data):
        """Renders the grouped data in the QTreeWidget."""
        self.tree.clear(); self.tree.setSortingEnabled(False)
        for group_key, items in sorted(grouped_data.items()):
            group_item = QTreeWidgetItem(self.tree, [f"{group_key} ({len(items)} items)"])
            group_item.setFlags(group_item.flags() | Qt.ItemIsAutoTristate | Qt.ItemIsUserCheckable)
            group_item.setCheckState(0, Qt.Checked)
            for res in items:
                child_item = QTreeWidgetItem(group_item, [res.url, str(res.final_status_code), str(res.content_length), res.title, str(res.num_redirects)])
        self.tree.setSortingEnabled(True); self.tree.sortByColumn(0, Qt.AscendingOrder)
