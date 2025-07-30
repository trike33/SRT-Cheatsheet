import os
import re
from urllib.parse import urlparse
from collections import Counter, defaultdict
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QDialog,
    QTableView, QHeaderView, QMessageBox, QPushButton, QHBoxLayout,
    QTextEdit, QDialogButtonBox, QTabWidget, QListWidget
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QStandardItemModel, QStandardItem

# --- Matplotlib Integration ---
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

class StatsChartCanvas(FigureCanvas):
    """A custom canvas for displaying matplotlib charts within a PyQt dialog."""
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        # Set the color scheme based on the application's theme
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
        """Generates a histogram for numeric data."""
        self.axes.clear()
        self.axes.hist(data, bins=20, color='#5e81ac', edgecolor='black')
        self.axes.set_title(title)
        self.axes.set_xlabel("Value")
        self.axes.set_ylabel("Frequency")
        self.fig.tight_layout()
        self.draw()

    def plot_bar_chart(self, labels, values, title):
        """Generates a horizontal bar chart for categorical data."""
        self.axes.clear()
        y_pos = range(len(labels))
        self.axes.barh(y_pos, values, align='center', color='#a3be8c')
        self.axes.set_yticks(y_pos)
        self.axes.set_yticklabels(labels)
        self.axes.invert_yaxis() # labels read top-to-bottom
        self.axes.set_xlabel('Count')
        self.axes.set_title(title)
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
        
        # Main Tab Widget
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        # --- Text Stats Tab ---
        text_stats_widget = QWidget()
        text_layout = QVBoxLayout(text_stats_widget)
        self.stats_text_edit = QTextEdit(readOnly=True)
        self.stats_text_edit.setFontFamily("Courier New")
        text_layout.addWidget(self.stats_text_edit)
        tab_widget.addTab(text_stats_widget, "Textual Report")

        # --- Charts Tab ---
        charts_widget = QWidget()
        charts_layout = QHBoxLayout(charts_widget)
        self.column_list = QListWidget()
        self.column_list.setMaximumWidth(200)
        self.column_list.itemClicked.connect(self.update_chart)
        self.chart_canvas = StatsChartCanvas(parent=self)
        charts_layout.addWidget(self.column_list)
        charts_layout.addWidget(self.chart_canvas)
        tab_widget.addTab(charts_widget, "Charts")

        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)
        
        self.process_data_for_display()

    def process_data_for_display(self):
        """Calculates stats and populates both the text report and chart view."""
        self.calculate_and_display_text_stats()
        self.populate_chart_columns()

    def calculate_and_display_text_stats(self):
        """Calculates and formats statistics for the text report."""
        stats_report = []
        for col in range(self.model.columnCount()):
            header = self.model.horizontalHeaderItem(col).text()
            stats_report.append(f"--- Statistics for Column: '{header}' ---\n")
            
            values = [self.model.item(row, col).text() for row in range(self.model.rowCount()) if self.model.item(row, col)]
            if not values:
                stats_report.append("No data in this column.\n\n")
                continue

            try:
                numeric_values = [float(v) for v in values]
                is_numeric = True
            except (ValueError, TypeError):
                numeric_values = []
                is_numeric = False

            if is_numeric and header.lower() in ['status code', 'length']:
                count, mean, median, std_dev = len(numeric_values), sum(numeric_values) / len(numeric_values), sorted(numeric_values)[len(numeric_values) // 2], (sum((x - (sum(numeric_values) / len(numeric_values))) ** 2 for x in numeric_values) / len(numeric_values)) ** 0.5
                stats_report.extend([f"  Type: Numeric", f"  Count: {count}", f"  Mean: {mean:.2f}", f"  Median: {median}", f"  Std Dev: {std_dev:.2f}", f"  Min: {min(numeric_values)}", f"  Max: {max(numeric_values)}\n"])
            else:
                value_counts = Counter(values)
                stats_report.extend([f"  Type: Textual", f"  Total Rows: {len(values)}", f"  Unique Values: {len(value_counts)}\n", "  Most Common Values:"])
                stats_report.extend([f"    - '{value}': {count} occurrences" for value, count in value_counts.most_common(15)])
                if len(value_counts) > 15: stats_report.append("    - ...and more.\n")
            stats_report.append("\n")

        self.stats_text_edit.setText("\n".join(stats_report))

    def populate_chart_columns(self):
        """Adds column headers to the list widget in the Charts tab."""
        for col in range(self.model.columnCount()):
            header = self.model.horizontalHeaderItem(col).text()
            self.column_list.addItem(header)

    def update_chart(self, item):
        """Generates and displays a chart for the selected column."""
        col_name = item.text()
        col_index = [i for i in range(self.model.columnCount()) if self.model.horizontalHeaderItem(i).text() == col_name][0]

        values = [self.model.item(row, col_index).text() for row in range(self.model.rowCount())]
        
        try:
            numeric_values = [float(v) for v in values]
            is_numeric = True
        except (ValueError, TypeError):
            is_numeric = False
        
        if is_numeric and col_name.lower() in ['status code', 'length']:
            self.chart_canvas.plot_histogram(numeric_values, f"Distribution of {col_name}")
        else:
            counts = Counter(values)
            top_15 = counts.most_common(15)
            labels, data = zip(*top_15)
            self.chart_canvas.plot_bar_chart(labels, data, f"Top 15 Most Common {col_name}s")


class PlaygroundWindow(QDialog):
    """A window for viewing and analyzing one or more httpx result files."""
    def __init__(self, file_paths, parent=None):
        super().__init__(parent)
        self.file_paths = file_paths
        
        title = f"Playground Viewer - {os.path.basename(file_paths[0])}" if len(file_paths) == 1 else f"Playground Viewer - {len(file_paths)} files"
        self.setWindowTitle(title)
        self.setGeometry(150, 150, 1000, 700)

        main_layout = QVBoxLayout(self)
        top_bar_layout = QHBoxLayout()
        self.stats_button = QPushButton("View Stats")
        self.stats_button.clicked.connect(self.show_stats)
        top_bar_layout.addStretch()
        top_bar_layout.addWidget(self.stats_button)
        main_layout.addLayout(top_bar_layout)
        
        self.table_view = QTableView()
        self.table_view.setSortingEnabled(True)
        main_layout.addWidget(self.table_view)
        
        self.model = QStandardItemModel()
        self.load_and_parse_data()

    def parse_httpx_file(self, file_path):
        records = []
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        line_regex = re.compile(r"^(?P<url>https?://[^\s]+)\s+\[\s*(?P<status_code>[\d,\s]+)\s*\]\s+\[\s*(?P<length>\d+)\s*\]\s+(?:\[\s*(?P<technology>[^\]]+)\s*\])?")

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
                        'schema': parsed_url.scheme,
                        'host': parsed_url.hostname,
                        'path': parsed_url.path,
                        'extension': extension if extension else 'N/A',
                        'status_code': int(final_status_code),
                        'length': int(data['length']),
                        'technology': data.get('technology', 'N/A').strip()
                    })
        except Exception as e:
            QMessageBox.critical(self, "File Error", f"Could not read or parse {os.path.basename(file_path)}: {e}")
        return records

    def load_and_parse_data(self):
        all_records = [rec for fp in self.file_paths for rec in self.parse_httpx_file(fp)]

        if not all_records:
            QMessageBox.warning(self, "No Data", "No valid data could be parsed from the selected file(s).")
            return

        headers = ['schema', 'host', 'path', 'extension', 'status_code', 'length', 'technology']
        self.model.setHorizontalHeaderLabels([h.replace('_', ' ').title() for h in headers])

        for record in all_records:
            row_items = []
            for header in headers:
                value = record.get(header)
                item = QStandardItem(str(value))
                if header in ['status_code', 'length']:
                    item.setData(value, Qt.UserRole)
                row_items.append(item)
            self.model.appendRow(row_items)

        self.table_view.setModel(self.model)
        self.table_view.resizeColumnsToContents()
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        
    def show_stats(self):
        if self.model.rowCount() == 0:
            QMessageBox.information(self, "No Data", "There is no data to analyze.")
            return
        dialog = StatisticsDialog(self.model, self)
        dialog.exec_()


class PlaygroundTabWidget(QWidget):
    """The main widget for the 'Playground' tab, using a grouped tree view."""
    def __init__(self, working_directory, icon_path, parent=None):
        super().__init__(parent)
        self.working_directory = working_directory
        self.icon_path = icon_path
        
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

    def refresh_playground(self):
        """Reloads and groups the contents of the CWD into the tree view."""
        self.tree_widget.clear()
        
        folder_icon = QIcon(os.path.join(self.icon_path, "folder.svg"))
        file_icon = QIcon(os.path.join(self.icon_path, "file.svg"))
        bag_icon = QIcon(os.path.join(self.icon_path, "bag.svg")) # Assuming you have a 'bag.svg'

        bags = {} # To hold parent "bag" items

        try:
            for item_name in sorted(os.listdir(self.working_directory)):
                full_path = os.path.join(self.working_directory, item_name)
                
                if os.path.isdir(full_path):
                    # Add directories as top-level items
                    dir_item = QTreeWidgetItem(self.tree_widget, [item_name])
                    dir_item.setIcon(0, folder_icon)
                    dir_item.setData(0, Qt.UserRole, full_path)
                
                elif "_" in item_name:
                    # Group files with an underscore into a "bag"
                    prefix = item_name.split('_')[0]
                    if prefix not in bags:
                        # Create a new bag if it doesn't exist
                        bags[prefix] = QTreeWidgetItem(self.tree_widget, [prefix])
                        bags[prefix].setIcon(0, bag_icon)
                    
                    # Add the file as a child of the bag
                    file_item = QTreeWidgetItem(bags[prefix], [item_name])
                    file_item.setIcon(0, file_icon)
                    file_item.setData(0, Qt.UserRole, full_path)
                
                else:
                    # Add ungrouped files as top-level items
                    file_item = QTreeWidgetItem(self.tree_widget, [item_name])
                    file_item.setIcon(0, file_icon)
                    file_item.setData(0, Qt.UserRole, full_path)
                    
        except Exception as e:
            QTreeWidgetItem(self.tree_widget, [f"Error reading directory: {e}"])

    def open_selected_items(self):
        """Opens the playground window for all selected files."""
        selected_items = self.tree_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select one or more files to open.")
            return
            
        file_paths = []
        for item in selected_items:
            path = item.data(0, Qt.UserRole)
            # Ensure the item is a file (has a path and is not a directory)
            if path and os.path.isfile(path):
                file_paths.append(path)
        
        if not file_paths:
            QMessageBox.warning(self, "No Files Selected", "Your selection does not contain any valid files. (Select the file names, not the bags).")
            return

        viewer_window = PlaygroundWindow(file_paths=file_paths, parent=self)
        viewer_window.exec_()

    def set_working_directory(self, path):
        self.working_directory = path
        self.refresh_playground()

    def apply_theme(self):
        self.refresh_playground()