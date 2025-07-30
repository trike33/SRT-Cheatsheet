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
    """Initializes the database only if it doesn't already exist."""
    db_exists = os.path.exists(DB_FILE)
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        command_text TEXT NOT NULL,
        run_in_background BOOLEAN NOT NULL DEFAULT 0,
        use_shell BOOLEAN NOT NULL DEFAULT 0,
        execution_order INTEGER UNIQUE
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )""")

    # If the database was just created, populate it with default data
    if not db_exists:
        default_commands = [
            # Command, is_background, use_shell, order
            ("internal:run_ipparser --scope_file {scope_file} --output scopeips", 0, 0, 1),
            ("httpx -title -tech-detect -sc -cl -fr -o httpx_out -l scopeips", 0, 0, 2),
            ("sudo naabu -hL scopeips -ports full -exclude-ports 80,443,8080,8443 -Pn -o naabu_out", 1, 0, 3),
            ("internal:run_domain_extracter --input httpx_out --output httpx_out_domains", 0, 0, 4),
            ("internal:run_domain_enum --subdomains httpx_out_domains --scope scopeips --output domains", 0, 0, 5),
            ("subfinder -dL domains -o subfinder_out", 1, 0, 6),
            # FIX: Use {{}} to escape braces for .format()
            ("while read -r ip; do nslookup \"$ip\" | awk '/name =/ {{print $4}}' >> reverse_dns_out; done < scopeips", 0, True, 7),
            ("internal:run_domain_enum --subdomains subfinder_out --scope scopeips --output subdomains", 0, 0, 8),
            ("internal:run_domain_enum --subdomains reverse_dns_out --scope scopeips --output subdomains", 0, 0, 9),
            ("httpx -title -tech-detect -sc -cl -fr -o httpx_out_subdomains -l subdomains", 0, 0, 10),
            ("internal:run_format_ips --input scopeips | httpx -title -tech-detect -sc -cl -fr -o httpx_out_80808443", 0, True, 11),
            ("httpx -title -tech-detect -sc -cl -fr -o httpx_out_extraports -l naabu_out", 0, 0, 12),
            ("katana -list subdomains -jc -o katana_out_subdomains", 1, 0, 13)
        ]
        cursor.executemany("INSERT INTO commands (command_text, run_in_background, use_shell, execution_order) VALUES (?, ?, ?, ?)", default_commands)
 
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

# --- NEW FUNCTION ---
def update_command(command_id, text, use_shell, order, background):
    """Updates a single command in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE commands
        SET command_text = ?, use_shell = ?, execution_order = ?, run_in_background = ?
        WHERE id = ?
    """, (text, use_shell, order, background, command_id))
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
