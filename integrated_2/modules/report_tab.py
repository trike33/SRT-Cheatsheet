from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel, QComboBox,
    QLineEdit, QTextEdit, QPushButton, QApplication, QMessageBox, QFrame
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon, QFont
from utils import db as command_db
from modules.dialogs import TemplateEditorDialog
import markdown

class ReportTabWidget(QWidget):
    """A tab for generating vulnerability reports from templates."""
    def __init__(self, parent=None):
        super().__init__(parent)
        
        main_layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)
        
        # --- Left Pane (Inputs) ---
        input_widget = QWidget()
        input_layout = QVBoxLayout(input_widget)
        
        category_layout = QHBoxLayout()
        category_layout.addWidget(QLabel("Vulnerability Category:"))
        manage_templates_btn = QPushButton("Manage Templates")
        category_layout.addStretch()
        category_layout.addWidget(manage_templates_btn)
        input_layout.addLayout(category_layout)
        
        self.category_combo = QComboBox()
        input_layout.addWidget(self.category_combo)
        
        input_layout.addWidget(QLabel("Vulnerable URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/page?param=value")
        input_layout.addWidget(self.url_input)
        
        input_layout.addWidget(QLabel("Custom Impact / Notes:"))
        self.impact_input = QTextEdit()
        self.impact_input.setPlaceholderText("Add custom details here...")
        input_layout.addWidget(self.impact_input)
        
        # --- Right Pane (Structured Preview) ---
        preview_widget = QWidget()
        preview_layout = QVBoxLayout(preview_widget)
        
        self.desc_preview = self.create_preview_section(preview_layout, "Description")
        self.impact_preview = self.create_preview_section(preview_layout, "Impact")
        self.validation_widgets = self.create_preview_section(preview_layout, "Validation Steps", navigation=True)
        self.fix_preview = self.create_preview_section(preview_layout, "Recommended Fix")
        
        splitter.addWidget(input_widget)
        splitter.addWidget(preview_widget)
        splitter.setSizes([400, 600])
        main_layout.addWidget(splitter)
        
        self.load_categories()
        manage_templates_btn.clicked.connect(self.open_template_editor)
        self.category_combo.currentIndexChanged.connect(self.generate_report)
        self.url_input.textChanged.connect(self.generate_report)
        self.impact_input.textChanged.connect(self.generate_report)
        
        self.generate_report()

    def create_preview_section(self, parent_layout, title, navigation=False):
        """Helper function to create a preview box, optionally with navigation."""
        section_layout = QVBoxLayout()
        
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel(f"<b>{title}</b>"))
        top_bar.addStretch()
        copy_btn = QPushButton("Copy")
        top_bar.addWidget(copy_btn)
        section_layout.addLayout(top_bar)

        text_edit = QTextEdit(readOnly=True)
        section_layout.addWidget(text_edit)
        
        copy_btn.clicked.connect(lambda: self.copy_to_clipboard(text_edit))
        
        if navigation:
            # --- FIX: Put navigation controls in their own container widget ---
            nav_container = QWidget()
            nav_layout = QHBoxLayout(nav_container)
            prev_btn = QPushButton("<")
            step_label = QLabel("Step 1 of 1")
            next_btn = QPushButton(">")
            nav_layout.addStretch()
            nav_layout.addWidget(prev_btn)
            nav_layout.addWidget(step_label)
            nav_layout.addWidget(next_btn)
            nav_layout.addStretch()
            section_layout.addWidget(nav_container)
            
            parent_layout.addLayout(section_layout)
            
            prev_btn.clicked.connect(self.show_previous_step)
            next_btn.clicked.connect(self.show_next_step)
            
            return {'preview': text_edit, 'nav_widget': nav_container, 'prev_btn': prev_btn, 'next_btn': next_btn, 'step_label': step_label}
        else:
            parent_layout.addLayout(section_layout)
            return text_edit

    def load_categories(self):
        current_selection = self.category_combo.currentText()
        self.category_combo.clear()
        categories = command_db.get_all_template_categories()
        self.category_combo.addItems(categories)
        index = self.category_combo.findText(current_selection)
        if index != -1:
            self.category_combo.setCurrentIndex(index)

    def open_template_editor(self):
        dialog = TemplateEditorDialog(self)
        dialog.exec_()
        self.load_categories()

    def generate_report(self):
        category = self.category_combo.currentText()
        if not category:
            self.desc_preview.clear()
            self.impact_preview.clear()
            self.validation_widgets['preview'].clear()
            self.validation_widgets['nav_widget'].setVisible(False)
            self.fix_preview.clear()
            return

        template_data = command_db.get_template_by_category(category)
        if not template_data: return

        url = self.url_input.text() or "{URL}"
        custom_impact = self.impact_input.toPlainText()
        
        self.desc_preview.setHtml(markdown.markdown(template_data.get('description', '').format(URL=url)))
        self.impact_preview.setHtml(markdown.markdown(custom_impact if custom_impact else template_data.get('impact', '')))
        self.fix_preview.setHtml(markdown.markdown(template_data.get('fix_recommendation', '')))
        
        self.validation_steps = [step.strip() for step in template_data.get('validation_steps', '').splitlines() if step.strip()]
        self.current_step_index = 0
        self.update_validation_step_view()

    def update_validation_step_view(self):
        if not self.validation_steps:
            self.validation_widgets['preview'].clear()
            self.validation_widgets['nav_widget'].setVisible(False)
            return

        self.validation_widgets['nav_widget'].setVisible(len(self.validation_steps) > 1)
        current_step_md = self.validation_steps[self.current_step_index]
        self.validation_widgets['preview'].setHtml(markdown.markdown(current_step_md))
        self.validation_widgets['step_label'].setText(f"Step {self.current_step_index + 1} of {len(self.validation_steps)}")
        self.validation_widgets['prev_btn'].setEnabled(self.current_step_index > 0)
        self.validation_widgets['next_btn'].setEnabled(self.current_step_index < len(self.validation_steps) - 1)

    def show_previous_step(self):
        if self.current_step_index > 0:
            self.current_step_index -= 1
            self.update_validation_step_view()

    def show_next_step(self):
        if self.current_step_index < len(self.validation_steps) - 1:
            self.current_step_index += 1
            self.update_validation_step_view()

    def copy_to_clipboard(self, text_widget):
        clipboard = QApplication.clipboard()
        clipboard.setText(text_widget.toPlainText())
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Copied to clipboard!")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        msg.show()
        QTimer.singleShot(1000, msg.accept)