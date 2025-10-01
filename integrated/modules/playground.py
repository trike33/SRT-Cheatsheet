import os
import re
from urllib.parse import urlparse
from collections import Counter
import webbrowser
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QDialog,
    QTableView, QHeaderView, QMessageBox, QPushButton, QHBoxLayout,
    QTextEdit, QDialogButtonBox, QTabWidget, QListWidget, QLabel, QMenu
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QStandardItemModel, QStandardItem, QColor, QBrush
from utils import db as command_db
from .dialogs import FuzzerDialog
import subprocess

# --- Matplotlib Integration ---
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

class StatsChartCanvas(FigureCanvas):
    """A custom canvas for displaying matplotlib charts within a PyQt dialog."""
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        is_dark_theme = "dark" in parent.styleSheet().lower()

        if is_dark_theme:
            plt.style.use('dark_background')
            self.fig = Figure(figsize=(width, height), dpi=dpi, facecolor='#2e3440')
            self.axes = self.fig.add_subplot(111, facecolor='#2e3440')
            self.axes.tick_params(axis='x', colors='white')
            self.axes.tick_params(axis='y', colors='white')
            self.axes.xaxis.label.set_color('white')
            self.axes.yaxis.label.set_color('white')
            self.axes.title.set_color('white')
        else:
            plt.style.use('default')
            self.fig = Figure(figsize=(width, height), dpi=dpi)
            self.axes = self.fig.add_subplot(111)

        super().__init__(self.fig)
        self.setParent(parent)

    def plot_histogram(self, data, title):
        self.axes.clear()
        self.axes.hist(data, bins=20, color='#88c0d0', edgecolor='#2e3440' if "dark" in self.parent().styleSheet().lower() else "white", linewidth=1.5)
        self.axes.set_title(title, fontsize=14, fontweight='bold')
        self.axes.set_xlabel("Value", fontsize=12)
        self.axes.set_ylabel("Frequency", fontsize=12)
        self.fig.tight_layout()
        self.draw()

    def plot_bar_chart(self, labels, values, title, xlabel='Count'):
        """Generic horizontal bar chart plotting with improved layout."""
        self.axes.clear()
        y_pos = range(len(labels))
        self.axes.barh(y_pos, values, align='center', color='#81a1c1', height=0.6)
        self.axes.set_yticks(y_pos)
        self.axes.set_yticklabels(labels, fontsize=9)
        self.axes.invert_yaxis()
        self.axes.set_xlabel(xlabel, fontsize=10)
        self.axes.set_title(title, fontsize=12, fontweight='bold')
        # Adjust layout to prevent labels from being cut off
        self.fig.tight_layout(rect=[0.1, 0, 0.9, 1])
        self.draw()

    def plot_pie_chart(self, labels, sizes, title):
        """Plots a pie chart."""
        self.axes.clear()
        is_dark_theme = "dark" in self.parent().styleSheet().lower()
        colors = ['#5e81ac', '#bf616a', '#d08770', '#a3be8c', '#b48ead']
        
        textprops = {'color': 'white' if is_dark_theme else 'black'}
        
        self.axes.pie(sizes, labels=labels, autopct='%1.1f%%',
                      shadow=True, startangle=90, colors=colors, textprops=textprops)
        self.axes.axis('equal')
        self.axes.set_title(title, fontsize=12, fontweight='bold')
        self.fig.tight_layout()
        self.draw()

class StatisticsDialog(QDialog):
    """A dialog with tabs for textual and graphical statistics."""
    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model
        self.setWindowTitle("Dataset Statistics")
        self.setGeometry(200, 200, 800, 600)
        layout = QVBoxLayout(self)
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)
        
        # Textual Report Tab
        text_stats_widget = QWidget()
        text_layout = QVBoxLayout(text_stats_widget)
        self.stats_text_edit = QTextEdit(readOnly=True)
        self.stats_text_edit.setFontFamily("Courier New")
        text_layout.addWidget(self.stats_text_edit)
        tab_widget.addTab(text_stats_widget, "Textual Report")
        
        # Charts Tab
        charts_widget = QWidget()
        charts_layout = QHBoxLayout(charts_widget)
        self.column_list = QListWidget()
        self.column_list.setMaximumWidth(200)
        self.column_list.itemClicked.connect(self.update_chart)
        self.chart_canvas = StatsChartCanvas(parent=self)
        charts_layout.addWidget(self.column_list)
        charts_layout.addWidget(self.chart_canvas)
        tab_widget.addTab(charts_widget, "Charts")
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)

        # Call the data processing methods
        self.calculate_and_display_text_stats()
        self.populate_chart_columns()

    def calculate_and_display_text_stats(self):
        """Calculates and displays statistics for each column in the model."""
        stats_report = []
        for col in range(self.model.columnCount()):
            header = self.model.horizontalHeaderItem(col).text()
            if header == '⭐': continue # Skip the star column

            stats_report.append(f"--- Statistics for Column: '{header}' ---\n")
            values = [self.model.item(row, col).text() for row in range(self.model.rowCount()) if self.model.item(row, col)]
            
            if not values:
                stats_report.append("No data in this column.\n\n")
                continue

            try:
                numeric_values = [float(v) for v in values]
                is_numeric = True
            except (ValueError, TypeError):
                is_numeric = False
            
            if is_numeric:
                count = len(numeric_values)
                mean = sum(numeric_values) / count
                median = sorted(numeric_values)[count // 2]
                std_dev = (sum((x - mean) ** 2 for x in numeric_values) / count) ** 0.5
                stats_report.extend([
                    f"  Type: Numeric",
                    f"  Count: {count}",
                    f"  Mean: {mean:.2f}",
                    f"  Median: {median}",
                    f"  Std Dev: {std_dev:.2f}",
                    f"  Min: {min(numeric_values)}",
                    f"  Max: {max(numeric_values)}\n"
                ])
            else:
                value_counts = Counter(values)
                stats_report.extend([
                    f"  Type: Textual",
                    f"  Total Rows: {len(values)}",
                    f"  Unique Values: {len(value_counts)}\n",
                    "  Most Common Values:"
                ])
                stats_report.extend([f"    - '{value}': {count} occurrences" for value, count in value_counts.most_common(15)])
                if len(value_counts) > 15:
                    stats_report.append("    - ...and more.\n")
            
            stats_report.append("\n")
        
        self.stats_text_edit.setText("\n".join(stats_report))

    def populate_chart_columns(self):
        """Adds chartable items to the list, including custom chart types."""
        self.column_list.clear()
        self.column_list.addItem("Status Code Distribution (Pie Chart)") # Custom pie chart
        
        for col in range(self.model.columnCount()):
            header = self.model.horizontalHeaderItem(col).text()
            if header in ['Status Code', 'Length', 'Technology', 'Title']: # Only show relevant columns for charting
                self.column_list.addItem(header)

    def update_chart(self, item):
        col_name = item.text()

        if col_name == "Status Code Distribution (Pie Chart)":
            status_codes = [int(self.model.item(row, 5).text()) for row in range(self.model.rowCount())]
            
            status_groups = {'2xx (Success)': 0, '3xx (Redirection)': 0, '4xx (Client Error)': 0, '5xx (Server Error)': 0, 'Other': 0}
            for code in status_codes:
                if 200 <= code < 300: status_groups['2xx (Success)'] += 1
                elif 300 <= code < 400: status_groups['3xx (Redirection)'] += 1
                elif 400 <= code < 500: status_groups['4xx (Client Error)'] += 1
                elif 500 <= code < 600: status_groups['5xx (Server Error)'] += 1
                else: status_groups['Other'] += 1
            
            # FIX: Correctly filter and extract labels and sizes
            labels = [k for k, v in status_groups.items() if v > 0]
            sizes = [v for k, v in status_groups.items() if v > 0]

            if labels:
                self.chart_canvas.plot_pie_chart(labels, sizes, "Status Code Distribution")
            return

        header_map = {self.model.horizontalHeaderItem(i).text(): i for i in range(self.model.columnCount())}
        col_index = header_map.get(col_name)
        
        if col_index is None: return

        values = [self.model.item(row, col_index).text() for row in range(self.model.rowCount())]

        if col_name == 'Length':
            # Create a sorted bar chart for all lengths
            numeric_values = sorted([(int(v), self.model.item(i, 2).text()) for i, v in enumerate(values) if v.isdigit()], reverse=True)
            if not numeric_values: return
            lengths, hosts = zip(*numeric_values)
            self.chart_canvas.plot_bar_chart(hosts, lengths, "Content Length by Host", xlabel="Length (bytes)")
        elif col_name in ['Technology', 'Title', 'Status Code']:
            # Use the bar chart logic for all items
            counts = Counter(values)
            all_items = counts.most_common() # Get all items
            if not all_items: return
            labels, data = zip(*all_items)
            self.chart_canvas.plot_bar_chart(labels, data, f"Distribution of {col_name}s")


class RiskAnalysisDialog(QDialog):
    """A dedicated window to display categorized, high-risk URLs."""
    def __init__(self, urls, parent=None):
        super().__init__(parent)
        self.urls = urls
        self.setWindowTitle("URL Risk Analysis")
        self.setGeometry(250, 250, 800, 700) # Increased height for the new section

        # --- Load Keywords from Database ---
        self.HIGH_RISK_KEYWORDS = command_db.get_high_risk_keywords()
        self.INTERESTING_KEYWORDS = command_db.get_interesting_keywords()
        self.SENSITIVE_EXTENSIONS = [
            ".xls", ".xml", ".xlsx", ".json", ".pdf", ".sql", ".doc", ".docx", 
            ".pptx", ".txt", ".zip", ".tar.gz", ".tgz", ".bak", ".7z", ".rar", 
            ".log", ".cache", ".secret", ".db", ".backup", ".yml", ".gz", 
            ".config", ".csv", ".yaml", ".md", ".md5", ".tar", ".xz", ".7zip", 
            ".p12", ".pem", ".key", ".crt", ".csr", ".sh", ".pl", ".py", 
            ".java", ".class", ".jar", ".war", ".ear", ".sqlitedb", ".sqlite3", 
            ".dbf", ".db3", ".accdb", ".mdb", ".sqlcipher", ".gitignore", ".env", 
            ".ini", ".conf", ".properties", ".plist", ".cfg"
        ]
        
        # --- Layout ---
        layout = QVBoxLayout(self)
        
        # High Risk Section
        layout.addWidget(QLabel("<h2>High Risk URLs</h2>"))
        self.high_risk_display = QTextEdit(readOnly=True)
        layout.addWidget(self.high_risk_display)
        
        # Interesting Section
        layout.addWidget(QLabel("<h2>Potentially Interesting URLs</h2>"))
        self.interesting_display = QTextEdit(readOnly=True)
        layout.addWidget(self.interesting_display)
        
        # --- New: Sensitive Extensions Section ---
        layout.addWidget(QLabel("<h2>URLs with Sensitive Extensions</h2>"))
        self.sensitive_ext_display = QTextEdit(readOnly=True)
        layout.addWidget(self.sensitive_ext_display)
        
        close_button = QDialogButtonBox(QDialogButtonBox.Close)
        close_button.rejected.connect(self.reject)
        layout.addWidget(close_button)
        
        self.analyze_and_display_urls()

    def analyze_and_display_urls(self):
        """Categorizes URLs and displays them in the appropriate text box."""
        high_risk_html = []
        interesting_html = []
        sensitive_ext_html = []

        for url in self.urls:
            is_high_risk = any(keyword in url.lower() for keyword in self.HIGH_RISK_KEYWORDS)
            is_interesting = any(keyword in url.lower() for keyword in self.INTERESTING_KEYWORDS)
            has_sensitive_ext = any(url.lower().endswith(ext) for ext in self.SENSITIVE_EXTENSIONS)

            if is_high_risk:
                high_risk_html.append(f'<span style="color: #bf616a;">{url}</span>')
            elif is_interesting:
                interesting_html.append(f'<span style="color: #ebcb8b;">{url}</span>')
                
            if has_sensitive_ext:
                sensitive_ext_html.append(f'<span style="color: #d08770;">{url}</span>')
        
        self.high_risk_display.setHtml("<br>".join(high_risk_html))
        self.interesting_display.setHtml("<br>".join(interesting_html))
        self.sensitive_ext_display.setHtml("<br>".join(sensitive_ext_html))

class NumericStandardItem(QStandardItem):
    def __lt__(self, other):
        try:
            return int(self.text()) < int(other.text())
        except ValueError:
            return self.text() < other.text()


class PlaygroundWindow(QDialog):
    """
    A window for viewing httpx results, with a separate dialog for risk analysis.
    """
    def __init__(self, file_paths, terminal_widget, working_directory, parent=None):
        super().__init__(parent)
        self.file_paths = file_paths
        self.terminal_widget = terminal_widget
        self.working_directory = working_directory
        self.starred_hosts = set()
        self.starred_hosts_file = os.path.join(self.working_directory, "starred_hosts.txt")
        self.load_starred_hosts()       
        title = f"Playground Viewer - {os.path.basename(file_paths[0])}" if len(file_paths) == 1 else f"Playground Viewer - {len(file_paths)} files"
        self.setWindowTitle(title)
        self.setGeometry(150, 150, 1100, 700)

        main_layout = QVBoxLayout(self)
        top_bar_layout = QHBoxLayout()
        
        self.risk_button = QPushButton("Analyze URL Risks")
        self.risk_button.clicked.connect(self.show_risk_analysis)
        top_bar_layout.addWidget(self.risk_button)
        
        top_bar_layout.addStretch()

        self.stats_button = QPushButton("View Stats")
        self.stats_button.clicked.connect(self.show_stats)
        top_bar_layout.addWidget(self.stats_button)

        main_layout.addLayout(top_bar_layout)
        
        self.table_view = QTableView()
        self.table_view.setSortingEnabled(True)
        main_layout.addWidget(self.table_view)
        
        self.model = QStandardItemModel()
        self.model.itemChanged.connect(self.on_item_changed)
        self.load_and_parse_data()

        self.table_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self.open_context_menu)
        self.table_view.doubleClicked.connect(self.on_cell_double_clicked)

    def load_starred_hosts(self):
        """Loads the list of starred hosts from a file."""
        if os.path.exists(self.starred_hosts_file):
            with open(self.starred_hosts_file, 'r') as f:
                self.starred_hosts = set(line.strip() for line in f)

    def save_starred_hosts(self):
        """Saves the current list of starred hosts to a file with error handling."""
        try:
            with open(self.starred_hosts_file, 'w') as f:
                for host in sorted(list(self.starred_hosts)):
                    f.write(host + '\n')
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Could not save starred hosts to {self.starred_hosts_file}:\n{e}")

    def on_item_changed(self, item):
        """Handles starring/unstarring of hosts and saves the changes."""
        if item.column() == 0: # Star column
            row = item.row()
            host_item = self.model.item(row, 2)
            if host_item:
                host = host_item.text()
                if item.checkState() == Qt.Checked:
                    self.starred_hosts.add(host)
                else:
                    self.starred_hosts.discard(host)
                self.save_starred_hosts()
    
    def on_item_changed(self, item):
        """Handles starring/unstarring of hosts."""
        if item.column() == 0: # Star column
            row = item.row()
            host_item = self.model.item(row, 2) # Host is now at column 2
            if host_item:
                host = host_item.text()
                if item.checkState() == Qt.Checked:
                    self.starred_hosts.add(host)
                else:
                    self.starred_hosts.discard(host)

    def on_cell_double_clicked(self, index):
        """Opens the URL in a browser when a host is double-clicked."""
        if index.column() == 2: # Host column
            self.open_in_browser(index.row())

    def open_context_menu(self, position):
        indexes = self.table_view.selectedIndexes()
        if not indexes:
            return
        
        row = indexes[0].row()
        
        menu = QMenu()
        if indexes[0].column() == 2: # Host column
            open_browser_action = menu.addAction("Open in default browser")
            open_burp_action = menu.addAction("Open with Burp's Chromium")
            fuzz_action = menu.addAction("Fuzz with ffuf")
            menu.addSeparator()

        colorize_menu = menu.addMenu("Colorize Row")
        colors = {"Red": "#bf616a", "Green": "#a3be8c", "Blue": "#81a1c1", "Yellow": "#ebcb8b", "None": None}
        for name, color_hex in colors.items():
            action = colorize_menu.addAction(name)
            action.triggered.connect(lambda checked, r=row, c=color_hex: self.colorize_row(r, c))

        action = menu.exec_(self.table_view.viewport().mapToGlobal(position))
        
        if 'open_browser_action' in locals() and action == open_browser_action:
            self.open_in_browser(row)
        elif 'open_burp_action' in locals() and action == open_burp_action:
            self.open_in_burp_browser(row)
        elif 'fuzz_action' in locals() and action == fuzz_action:
            self.open_fuzzer_dialog(row)

    def colorize_row(self, row, color_hex):
        """Applies a background color to an entire row."""
        for col in range(self.model.columnCount()):
            item = self.model.item(row, col)
            if item:
                if color_hex:
                    item.setBackground(QBrush(QColor(color_hex)))
                else:
                    item.setBackground(QBrush()) # Reset to default
            
    def get_url_from_row(self, row):
        schema = self.model.item(row, 1).text() # Schema is at column 1
        host = self.model.item(row, 2).text()   # Host is at column 2
        path = self.model.item(row, 3).text() if self.model.item(row, 3) else ''
        return f"{schema}://{host}{path}"

    def colorize_status_code(self, item, status_code):
        """Sets the background color of a status code item based on its value."""
        if 200 <= status_code < 300:
            color = QColor("green")
        elif 300 <= status_code < 400:
            color = QColor("blue")
        elif 400 <= status_code < 500:
            color = QColor("orange")
        elif 500 <= status_code < 600:
            color = QColor("red")
        else:
            # Should not happen, but as a fallback
            color = QColor("white")
            
        item.setForeground(color)

    def load_and_parse_data(self):
        """Loads data into the main table view."""
        self.all_records = [rec for fp in self.file_paths for rec in self.parse_httpx_file(fp)]
        if not self.all_records:
            QMessageBox.warning(self, "No Data", "No valid data could be parsed.")
            return

        headers = ['⭐', 'Schema', 'Host', 'Path', 'Extension', 'Status Code', 'Length', 'Technology']
        self.model.setHorizontalHeaderLabels(headers)

        for record in self.all_records:
            host = record.get('host', '')
            star_item = QStandardItem()
            star_item.setCheckable(True)
            if host in self.starred_hosts:
                star_item.setCheckState(Qt.Checked)
            
            status_code = int(record.get('status_code', 0))
            status_item = NumericStandardItem(f"{status_code:d}")
            self.colorize_status_code(status_item, status_code)
            
            row_items = [
                star_item,
                QStandardItem(str(record.get('schema', ''))),
                QStandardItem(host),
                QStandardItem(str(record.get('path', ''))),
                QStandardItem(str(record.get('extension', ''))),
                status_item,
                NumericStandardItem(f"{record.get('length', 0):d}"),
                QStandardItem(str(record.get('technology', '')))
            ]
            self.model.appendRow(row_items)

        self.table_view.setModel(self.model)
        self.table_view.resizeColumnsToContents()
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table_view.setColumnWidth(0, 30)
    
    def on_cell_double_clicked(self, index):
        """Opens the URL in a browser when a host is double-clicked."""
        if index.column() == 1: # Host column
            self.open_in_browser(index.row())

    def open_context_menu(self, position):
        index = self.table_view.indexAt(position)
        if not index.isValid():
            return
            
        row = index.row()
        
        menu = QMenu()
        
        # --- Row-level Actions ---
        colorize_menu = menu.addMenu("Colorize Row")
        colors = {"Red": "#bf616a", "Green": "#a3be8c", "Blue": "#81a1c1", "Yellow": "#ebcb8b", "None": None}
        for name, color_hex in colors.items():
            action = colorize_menu.addAction(name)
            action.triggered.connect(lambda checked, r=row, c=color_hex: self.colorize_row(r, c))

        # --- Host-specific Actions ---
        if index.column() == 2: # Only show these for the 'Host' column
            menu.addSeparator()
            open_browser_action = menu.addAction("Open in default browser")
            open_burp_action = menu.addAction("Open with Burp's Chromium")
            fuzz_action = menu.addAction("Fuzz with ffuf")
            
            # Execute the menu and handle the selected action
            action = menu.exec_(self.table_view.viewport().mapToGlobal(position))
            
            if action == open_browser_action:
                self.open_in_browser(row)
            elif action == open_burp_action:
                self.open_in_burp_browser(row)
            elif action == fuzz_action:
                self.open_fuzzer_dialog(row)
        else:
            # For other columns, just show the colorize menu
            menu.exec_(self.table_view.viewport().mapToGlobal(position))
            
    def get_url_from_row(self, row):
        schema = self.model.item(row, 0).text()
        host = self.model.item(row, 1).text()
        path = self.model.item(row, 2).text() if self.model.item(row, 2) else ''
        return f"{schema}://{host}{path}"

    def open_in_browser(self, row):
        url = self.get_url_from_row(row)
        webbrowser.open_new_tab(url)
        
    def open_in_burp_browser(self, row):
        url = self.get_url_from_row(row)
        try:
            chromium_path = "/usr/bin/chromium" 
            subprocess.Popen([chromium_path, "--proxy-server=127.0.0.1:8080", "--ignore-certificate-errors", url])
        except FileNotFoundError:
            QMessageBox.critical(self, "Browser Not Found", "Could not find Chromium. Please ensure it's installed and in your PATH.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not launch browser: {e}")

    def open_fuzzer_dialog(self, row):
        url = self.get_url_from_row(row)
        # Ensure the URL for fuzzing ends with a slash
        if not url.endswith('/'):
            url += '/'
        dialog = FuzzerDialog(url=url, parent=self)
        if dialog.exec_() == QDialog.Accepted and dialog.command:
            self.terminal_widget.add_command_to_slot(dialog.command)

    def show_risk_analysis(self):
        """Opens the new dialog for viewing categorized risks."""
        if not hasattr(self, 'all_records') or not self.all_records:
            QMessageBox.information(self, "No Data", "There are no URLs to analyze.")
            return
        
        # Compile a list of full URLs to pass to the dialog
        full_urls = [
            f"{rec.get('schema', '')}://{rec.get('host', '')}{rec.get('path', '')}" 
            for rec in self.all_records
        ]
        
        dialog = RiskAnalysisDialog(full_urls, self)
        dialog.exec_()

    def parse_httpx_file(self, file_path):
        """Parses a single httpx output file."""
        records = []
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        line_regex = re.compile(
            r"^(?P<url>https?://[^\s]+)\s+"
            r"\[\s*(?P<status_code>[\d,\s]+)\s*\]\s+"
            r"\[\s*(?P<length>\d+)\s*\]\s+"
            r"(?:\[\s*(?P<technology>[^\]]+)\s*\])?"
        )
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    clean_line = ansi_escape.sub('', line).strip()
                    match = line_regex.match(clean_line)
                    if not match: continue
                    data = match.groupdict()
                    parsed_url = urlparse(data['url'])
                    final_status_code = data['status_code'].split(',')[-1].strip()
                    _, extension = os.path.splitext(parsed_url.path)
                    records.append({
                        'schema': parsed_url.scheme, 'host': parsed_url.hostname, 'path': parsed_url.path,
                        'extension': extension if extension else 'N/A', 'status_code': int(final_status_code),
                        'length': int(data['length']), 'technology': data.get('technology', 'N/A').strip()
                    })
        except Exception as e:
            QMessageBox.critical(self, "File Error", f"Could not read/parse {os.path.basename(file_path)}: {e}")
        return records

    def show_stats(self):
        if self.model.rowCount() == 0:
            QMessageBox.information(self, "No Data", "There is no data to analyze.")
            return
        dialog = StatisticsDialog(self.model, self)
        dialog.exec_()

class PlaygroundTabWidget(QWidget):
    """The main widget for the 'Playground' tab, using a grouped tree view."""
    def __init__(self, working_directory, icon_path, terminal_widget, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.icon_path = icon_path
        self.terminal_widget = terminal_widget
        
        layout = QVBoxLayout(self)
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderHidden(True)
        self.tree_widget.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.tree_widget.itemDoubleClicked.connect(self.open_selected_items)
        layout.addWidget(self.tree_widget)
        
        open_button_layout = QHBoxLayout()
        open_button = QPushButton("Open Selected File(s)")
        open_button.clicked.connect(self.open_selected_items)
        open_button_layout.addStretch()
        open_button_layout.addWidget(open_button)
        layout.addLayout(open_button_layout)
        
        self.refresh_playground()

    def open_selected_items(self):
        selected_items = self.tree_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select one or more files to open.")
            return
        file_paths = []
        for item in selected_items:
            path = item.data(0, Qt.UserRole)
            if path and os.path.isfile(path):
                file_paths.append(path)
        if not file_paths:
            QMessageBox.warning(self, "No Files Selected", "Your selection does not contain any valid files.")
            return
            
        viewer_window = PlaygroundWindow(
            file_paths=file_paths, 
            terminal_widget=self.terminal_widget, 
            working_directory=self.working_directory, 
            parent=self
        )
        viewer_window.exec_()

    def set_working_directory(self, path):
        """Updates the working directory and refreshes the file view."""
        self.working_directory = path
        self.refresh_playground()

    def refresh_playground(self):
        self.tree_widget.clear()
        folder_icon = QIcon(os.path.join(self.icon_path, "folder.svg"))
        file_icon = QIcon(os.path.join(self.icon_path, "file.svg"))
        bag_icon = QIcon(os.path.join(self.icon_path, "bag.svg"))

        bags = {}

        try:
            for item_name in sorted(os.listdir(self.working_directory)):
                full_path = os.path.join(self.working_directory, item_name)
                if os.path.isdir(full_path):
                    dir_item = QTreeWidgetItem(self.tree_widget, [item_name])
                    dir_item.setIcon(0, folder_icon)
                    dir_item.setData(0, Qt.UserRole, full_path)
                elif "_" in item_name:
                    prefix = item_name.split('_')[0]
                    if prefix not in bags:
                        bags[prefix] = QTreeWidgetItem(self.tree_widget, [prefix])
                        bags[prefix].setIcon(0, bag_icon)
                    file_item = QTreeWidgetItem(bags[prefix], [item_name])
                    file_item.setIcon(0, file_icon)
                    file_item.setData(0, Qt.UserRole, full_path)
                else:
                    file_item = QTreeWidgetItem(self.tree_widget, [item_name])
                    file_item.setIcon(0, file_icon)
                    file_item.setData(0, Qt.UserRole, full_path)
        except Exception as e:
            QTreeWidgetItem(self.tree_widget, [f"Error reading directory: {e}"])

    def apply_theme(self):
        self.refresh_playground()
        
    def open_fuzzer_dialog(self):
        selected_items = self.table_view.selectedIndexes()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select a host to fuzz.")
            return

        row = selected_items[0].row()
        schema = self.model.item(row, 0).text()
        host = self.model.item(row, 1).text()
        url = f"{schema}://{host}/"

        dialog = FuzzerDialog(url=url, parent=self)
        if dialog.exec_() == QDialog.Accepted and dialog.command:
            self.fuzz_command_generated.emit(dialog.command)