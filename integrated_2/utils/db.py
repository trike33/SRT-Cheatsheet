import sqlite3
import os

DB_FILE = "recon_automator.db"

# New, more colorful dark theme stylesheet
dark_theme_stylesheet = """
    QWidget {
        background-color: #2e3440;
        color: #d8dee9;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    QPushButton {
        background-color: #434c5e;
        border: 1px solid #4c566a;
        padding: 5px;
        border-radius: 3px;
        color: #eceff4;
    }
    QPushButton:hover {
        background-color: #4c566a;
    }
    QPushButton:pressed {
        background-color: #3b4252;
    }
    QPushButton#StartButton {
        background-color: #5e81ac; /* A calm blue */
    }
    QPushButton#StopButton {
        background-color: #bf616a; /* A soft red */
    }
    QLineEdit, QTextEdit, QListView, QTreeView, QListWidget, QTableView {
        background-color: #3b4252;
        border: 1px solid #4c566a;
        padding: 5px;
        color: #d8dee9;
        selection-background-color: #5e81ac; /* Use primary blue for selection */
    }
    QTabWidget::pane {
        border-top: 2px solid #434c5e;
    }
    QTabBar::tab {
        background: #2e3440;
        border: 1px solid #2e3440;
        padding: 10px;
        color: #d8dee9;
    }
    QTabBar::tab:selected {
        background: #434c5e;
        border-bottom: 2px solid #88c0d0; /* A cyan accent for the selected tab */
    }
    QTabBar::tab:!selected:hover {
        background: #3b4252;
    }
    QProgressBar {
        border: 1px solid #4c566a;
        border-radius: 5px;
        text-align: center;
        color: #eceff4;
    }
    QProgressBar::chunk {
        background-color: #a3be8c; /* A nice green for progress */
        width: 20px;
    }
    QHeaderView::section {
        background-color: #434c5e;
        color: #eceff4;
        padding: 4px;
        border: 1px solid #4c566a;
    }
"""

# New, more colorful light theme stylesheet
light_theme_stylesheet = """
    QWidget {
        background-color: #ffffff;
        color: #2e3440;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    QPushButton {
        background-color: #f0f0f0;
        border: 1px solid #dcdcdc;
        padding: 5px;
        border-radius: 3px;
    }
    QPushButton:hover {
        background-color: #e0e0e0;
        border-color: #c0c0c0;
    }
    QPushButton:pressed {
        background-color: #d0d0d0;
    }
    QPushButton#StartButton {
        background-color: #0078d4; /* A vibrant blue */
        color: white;
    }
    QPushButton#StopButton {
        background-color: #d13438; /* A strong red */
        color: white;
    }
    QLineEdit, QTextEdit, QListView, QTreeView, QListWidget, QTableView {
        background-color: #ffffff;
        border: 1px solid #dcdcdc;
        padding: 5px;
        color: #2e3440;
        selection-background-color: #0078d4; /* Use primary blue for selection */
        selection-color: white;
    }
    QTabWidget::pane {
        border-top: 2px solid #e0e0e0;
    }
    QTabBar::tab {
        background: #f0f0f0;
        border: 1px solid #dcdcdc;
        padding: 10px;
    }
    QTabBar::tab:selected {
        background: #ffffff;
        border-bottom: 2px solid #0078d4; /* Blue accent for selected tab */
    }
    QTabBar::tab:!selected:hover {
        background: #e5f1fb;
    }
    QProgressBar {
        border: 1px solid #dcdcdc;
        border-radius: 5px;
        text-align: center;
        color: #2e3440;
        background-color: #f0f0f0;
    }
    QProgressBar::chunk {
        background-color: #28a745; /* A bright green for progress */
        width: 20px;
    }
    QHeaderView::section {
        background-color: #f0f0f0;
        color: #2e3440;
        padding: 4px;
        border: 1px solid #dcdcdc;
    }
"""

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    return sqlite3.connect(DB_FILE)

def initialize_db():
    """Initializes the database with necessary tables and default data."""
    if os.path.exists(DB_FILE):
        return

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Commands Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        command_text TEXT NOT NULL,
        run_in_background BOOLEAN NOT NULL DEFAULT 0,
        use_shell BOOLEAN NOT NULL DEFAULT 0,
        execution_order INTEGER UNIQUE
    )""")
    
    # Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )""")
    
    # Default commands and settings
    default_commands = [
        ('internal:run_domain_extracter --input root_domains.txt --output subdomains.txt', 0, 0, 1),
        ('subfinder -dL scope_domains.txt -o subfinder_out.txt', 1, 0, 2),
        ('internal:run_domain_enum --subdomains subdomains.txt --scope scope_domains.txt --output final_subdomains.txt', 0, 0, 3)
    ]
    
    cursor.executemany("INSERT INTO commands (command_text, run_in_background, use_shell, execution_order) VALUES (?, ?, ?, ?)", default_commands)
    
    default_settings = {
        'dark_theme_stylesheet': dark_theme_stylesheet,
        'light_theme_stylesheet': light_theme_stylesheet,
        'active_theme': 'dark'
    }
    
    for key, value in default_settings.items():
        cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))

    conn.commit()
    conn.close()

def get_all_commands():
    """Retrieves all commands from the database, ordered by execution order."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM commands ORDER BY execution_order")
    commands = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return commands

def save_commands(commands):
    """Saves the entire list of commands, replacing old ones."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM commands")
    cursor.executemany("INSERT INTO commands (command_text, run_in_background, use_shell, execution_order) VALUES (?, ?, ?, ?)",
                       [(c['command_text'], c['run_in_background'], c['use_shell'], c['execution_order']) for c in commands])
    conn.commit()
    conn.close()

def get_setting(key):
    """Retrieves a specific setting value by key."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def set_setting(key, value):
    """Sets a specific setting value."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def toggle_theme():
    """Switches the active theme between 'light' and 'dark'."""
    current_theme = get_setting('active_theme')
    new_theme = 'light' if current_theme == 'dark' else 'dark'
    set_setting('active_theme', new_theme)