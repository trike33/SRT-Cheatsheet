import sqlite3
import os

# --- Constants ---
DB_FILE = "recon_commands.db"

# --- Default Commands ---
# Using a list of dictionaries for better readability and maintenance.
DEFAULT_COMMANDS = [
    {'text': 'internal:run_ipparser', 'shell': False, 'order': 10, 'bg': False},
    {'text': 'httpx -title -tech-detect -sc -cl -fr -o httpx_out -l scopeips', 'shell': False, 'order': 20, 'bg': False},
    {'text': 'sudo naabu -hL scopeips -ports full -exclude-ports 80,443,8080,8443 -Pn -o naabu_out', 'shell': False, 'order': 30, 'bg': True},
    {'text': 'internal:run_domain_extracter --input httpx_out --output httpx_out_domains', 'shell': False, 'order': 40, 'bg': False},
    {'text': 'internal:run_domain_enum --subdomains httpx_out_domains --scope scopeips --output domains', 'shell': False, 'order': 50, 'bg': False},
    {'text': 'subfinder -dL domains -o subfinder_out', 'shell': False, 'order': 60, 'bg': False},
    {'text': "while read -r ip; do nslookup \"$ip\" | awk '/name =/ {{print $4}}' >> reverse_dns_out; done < scopeips", 'shell': True, 'order': 70, 'bg': False},
    {'text': 'internal:run_domain_enum --subdomains subfinder_out --scope scopeips --output subdomains', 'shell': False, 'order': 80, 'bg': False},
    {'text': 'internal:run_domain_enum --subdomains reverse_dns_out --scope scopeips --output subdomains', 'shell': False, 'order': 90, 'bg': False},
    {'text': 'httpx -title -tech-detect -sc -cl -fr -o httpx_out_subdomains -l subdomains', 'shell': False, 'order': 100, 'bg': False},
    {'text': 'internal:run_format_ips --input scopeips | httpx -title -tech-detect -sc -cl -fr -o httpx_out_80808443', 'shell': True, 'order': 110, 'bg': False},
    {'text': 'httpx -title -tech-detect -sc -cl -fr -o httpx_out_extraports -l naabu_out', 'shell': False, 'order': 120, 'bg': False}
]

# --- Default Theme Stylesheets ---
DARK_THEME_STYLESHEET = """
QWidget {
    background-color: #2b2b2b;
    color: #f0f0f0;
    border: none;
}
QMainWindow {
    background-color: #2b2b2b;
}
QDialog {
    background-color: #3c3c3c;
}
QLineEdit, QTextEdit, QSpinBox {
    background-color: #3c3c3c;
    color: #f0f0f0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 5px;
}
QPushButton {
    background-color: #555;
    color: #f0f0f0;
    border: 1px solid #666;
    border-radius: 4px;
    padding: 8px;
}
QPushButton:hover {
    background-color: #666;
}
QPushButton:pressed {
    background-color: #777;
}
#StartButton {
    background-color: #007BFF;
    font-weight: bold;
}
#StartButton:hover {
    background-color: #008cff;
}
#StopButton {
    background-color: #DC3545;
    font-weight: bold;
}
#StopButton:hover {
    background-color: #ef4656;
}
QHeaderView::section {
    background-color: #555;
    padding: 4px;
    border: 1px solid #666;
}
QTableWidget {
    gridline-color: #555;
}
"""

LIGHT_THEME_STYLESHEET = """
QWidget {
    background-color: #f0f0f0;
    color: #000000;
    border: none;
}
QMainWindow {
    background-color: #f0f0f0;
}
QDialog {
    background-color: #ffffff;
}
QLineEdit, QTextEdit, QSpinBox {
    background-color: #ffffff;
    color: #000000;
    border: 1px solid #ccc;
    border-radius: 4px;
    padding: 5px;
}
QPushButton {
    background-color: #e0e0e0;
    color: #000000;
    border: 1px solid #ccc;
    border-radius: 4px;
    padding: 8px;
}
QPushButton:hover {
    background-color: #d0d0d0;
}
QPushButton:pressed {
    background-color: #c0c0c0;
}
#StartButton {
    background-color: #007BFF;
    color: white;
    font-weight: bold;
}
#StartButton:hover {
    background-color: #008cff;
}
#StopButton {
    background-color: #DC3545;
    color: white;
    font-weight: bold;
}
#StopButton:hover {
    background-color: #ef4656;
}
QHeaderView::section {
    background-color: #e0e0e0;
    padding: 4px;
    border: 1px solid #ccc;
}
QTableWidget {
    gridline-color: #ccc;
}
"""

def get_db_connection():
    """Establishes and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_db():
    """Initializes the database and ensures the schema is up-to-date."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # --- Commands Table ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command_text TEXT NOT NULL,
            use_shell BOOLEAN NOT NULL CHECK (use_shell IN (0, 1)),
            execution_order INTEGER UNIQUE NOT NULL
        );
    """)

    # --- Schema Migration: Add 'run_in_background' column if it doesn't exist ---
    cursor.execute("PRAGMA table_info(commands)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'run_in_background' not in columns:
        cursor.execute("""
            ALTER TABLE commands 
            ADD COLUMN run_in_background BOOLEAN NOT NULL CHECK (run_in_background IN (0, 1)) DEFAULT 0;
        """)
        print("Database schema updated: Added 'run_in_background' column.")

    # Populate with default commands if empty
    cursor.execute("SELECT COUNT(id) FROM commands")
    if cursor.fetchone()[0] == 0:
        for cmd in DEFAULT_COMMANDS:
             cursor.execute(
                "INSERT INTO commands (command_text, use_shell, execution_order, run_in_background) VALUES (:text, :shell, :order, :bg)",
                cmd
            )

    # --- Settings Table ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    cursor.execute("SELECT COUNT(key) FROM settings")
    if cursor.fetchone()[0] == 0:
        settings_data = [
            ('active_theme', 'dark'),
            ('dark_theme_stylesheet', DARK_THEME_STYLESHEET),
            ('light_theme_stylesheet', LIGHT_THEME_STYLESHEET)
        ]
        cursor.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", settings_data)
        
    conn.commit()
    conn.close()

def get_setting(key):
    """Retrieves a specific setting's value from the database."""
    conn = get_db_connection()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row['value'] if row else None

def update_setting(key, value):
    """Updates a specific setting's value in the database."""
    conn = get_db_connection()
    conn.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
    conn.commit()
    conn.close()

def get_all_commands():
    """Retrieves all commands from the database, sorted by execution order."""
    conn = get_db_connection()
    commands = conn.execute("SELECT id, command_text, use_shell, execution_order, run_in_background FROM commands ORDER BY execution_order ASC").fetchall()
    conn.close()
    return commands

def add_command(command_text, use_shell, execution_order, run_in_background):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO commands (command_text, use_shell, execution_order, run_in_background) VALUES (?, ?, ?, ?)",
            (command_text, use_shell, execution_order, run_in_background)
        )
        conn.commit()
    finally:
        conn.close()

def update_command(command_id, command_text, use_shell, execution_order, run_in_background):
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE commands SET command_text = ?, use_shell = ?, execution_order = ?, run_in_background = ? WHERE id = ?",
            (command_text, use_shell, execution_order, run_in_background, command_id)
        )
        conn.commit()
    finally:
        conn.close()

def delete_command(command_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM commands WHERE id = ?", (command_id,))
    conn.commit()
    conn.close()

# --- Initialize the database on module import ---
initialize_db()
