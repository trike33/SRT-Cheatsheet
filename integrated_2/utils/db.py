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
    """Ensures all tables exist on startup and populates them if the DB is new."""
    db_exists = os.path.exists(DB_FILE)
    conn = get_db_connection()
    cursor = conn.cursor()

    # --- Standard Tables ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT, command_text TEXT NOT NULL,
        run_in_background BOOLEAN NOT NULL DEFAULT 0, use_shell BOOLEAN NOT NULL DEFAULT 0,
        execution_order INTEGER UNIQUE )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sudo_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT, command_text TEXT NOT NULL UNIQUE )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT )""")
        
    # --- NEW: Keyword Tables ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS high_risk_keywords ( id INTEGER PRIMARY KEY, keyword TEXT NOT NULL UNIQUE )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS interesting_keywords ( id INTEGER PRIMARY KEY, keyword TEXT NOT NULL UNIQUE )""")

   # Report templates table 
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS report_templates (
        id INTEGER PRIMARY KEY,
        category TEXT NOT NULL UNIQUE,
        description TEXT,
        impact TEXT,
        validation_steps TEXT,
        fix_recommendation TEXT
    )""")

    # --- Populate with default data ONLY if the database file is new ---
    if not db_exists:
        # (Default commands and sudo_commands insertion remains the same)
        
        # --- NEW: Default Keywords ---
        high_risk_words = [
            ('admin',), ('config',), ('settings',), ('database',), ('db',), ('sql',), ('query',),
            ('secret',), ('token',), ('jwt',), ('auth',), ('login',), ('password',), ('passwd',),
            ('backup',), ('dump',), ('export',), ('import',), ('debug',), ('trace',), ('logs',),
            ('internal',), ('private',), ('root',), ('master',), ('prod',), ('staging',)
        ]
        interesting_words = [
            ('api',), ('rest',), ('graphql',), ('swagger',), ('openapi',), ('v1',), ('v2',), ('v3',),
            ('json',), ('xml',), ('rpc',), ('dev',), ('test',), ('poc',), ('beta',), ('alpha',),
            ('docs',), ('documentation',), ('gateway',), ('proxy',), ('user',), ('account',),
            ('payment',), ('billing',), ('checkout',), ('upload',), ('download',)
        ]
        cursor.executemany("INSERT INTO high_risk_keywords (keyword) VALUES (?)", high_risk_words)
        cursor.executemany("INSERT INTO interesting_keywords (keyword) VALUES (?)", interesting_words)

    # --- Populate with default data ONLY if the database file is new ---
    if not db_exists:
        # Default standard commands
        default_commands = [
            ("internal:run_ipparser --scope_file {scope_file} --output scopeips", 0, 0, 1),
            ("httpx -title -tech-detect -sc -cl -fr -o httpx_out -l scopeips", 0, 0, 2),
            ("internal:run_domain_enum --subdomains httpx_out_domains --scope scopeips --output domains", 0, 0, 3),
            ("subfinder -dL domains -o subfinder_out", 0, 0, 4),
            ("internal:run_reverse_dns --input scopeips --output reverse_dns_out", 0, 0, 5),
            ("internal:run_domain_enum --subdomains subfinder_out --scope scopeips --output subdomains", 0, 0, 6),
            ("internal:run_domain_enum --subdomains reverse_dns_out --scope scopeips --output subdomains", 0, 0, 7),
            ("httpx -title -tech-detect -sc -cl -fr -o httpx_out_subdomains -l subdomains", 0, 0, 8),
            ("internal:run_format_ips --input scopeips --output scopeips_80808443", 0, 0, 9),
            ("httpx -l scopeips_80808443 -title -tech-detect -sc -cl -fr -o httpx_out_80808443", 0, 0, 10),
            ("katana -list subdomains -jc -o katana_out_subdomains", 0, 0, 11)
        ]
        cursor.executemany("INSERT INTO commands (command_text, run_in_background, use_shell, execution_order) VALUES (?, ?, ?, ?)", default_commands)
        
        # Default sudo commands
        default_sudo_commands = [
            ("sudo naabu -hL scopeips -ports full -exclude-ports 80,443,8080,8443 -Pn -o naabu_out",)
        ]
        cursor.executemany("INSERT INTO sudo_commands (command_text) VALUES (?)", default_sudo_commands)

        # Default settings
        default_settings = {
            'dark_theme_stylesheet': dark_theme_stylesheet,
            'light_theme_stylesheet': light_theme_stylesheet,
            'active_theme': 'dark'
        }
        for key, value in default_settings.items():
            cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))

       # Default templates   
        default_templates = [
            (
                'Cross-Site Scripting (XSS)',
                "The application is vulnerable to Cross-Site Scripting (XSS). The endpoint at {URL} does not properly sanitize user-supplied input, allowing an attacker to inject malicious scripts. These scripts are then executed in the victim's browser.",
                "An attacker could hijack user sessions, deface the website, or redirect users to malicious sites, leading to credential theft and a loss of trust in the application.",
                "1. Navigate to the vulnerable URL.\n2. Insert a standard XSS payload, such as `<script>alert('XSS')</script>`, into the affected parameter.\n3. Observe that the script executes in the browser.",
                "Implement context-aware output encoding on all user-supplied data. Utilize a Content Security Policy (CSP) to restrict the sources from which scripts can be loaded."
            ),
            (
                'SQL Injection (SQLi)',
                "The application is vulnerable to SQL Injection. A parameter at the specified URL ({URL}) is directly used in a database query without proper sanitization, allowing an attacker to manipulate the query's logic.",
                "Successful exploitation could lead to unauthorized access to sensitive data, modification or deletion of data, and potentially full server compromise.",
                "1. Identify the vulnerable parameter in the URL.\n2. Submit a payload like `' OR 1=1 --`.\n3. Confirm that the application's response is altered, indicating that the query was manipulated (e.g., a successful login without a valid password).",
                "Use parameterized queries (prepared statements) for all database interactions. Avoid building SQL queries with string concatenation. Enforce the principle of least privilege for database users."
            )
        ]
        cursor.executemany("""
            INSERT INTO report_templates (category, description, impact, validation_steps, fix_recommendation)
            VALUES (?, ?, ?, ?, ?)
        """, default_templates)

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

def add_command(text, use_shell, background):
    """
    Adds a new command to the database, automatically assigning it the next execution order.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # --- FIX: Automatically determine the next execution order ---
    cursor.execute("SELECT MAX(execution_order) FROM commands")
    max_order = cursor.fetchone()[0]
    new_order = (max_order or 0) + 1

    cursor.execute("""
        INSERT INTO commands (command_text, use_shell, execution_order, run_in_background)
        VALUES (?, ?, ?, ?)
    """, (text, use_shell, new_order, background))
    conn.commit()
    conn.close()


# --- NEW FUNCTION ---
def delete_command(command_id):
    """Deletes a command from the database by its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM commands WHERE id = ?", (command_id,))
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

# --- NEW: Functions for Sudo Commands ---
def get_all_sudo_commands():
    """Retrieves all sudo commands from the database."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sudo_commands ORDER BY command_text")
    commands = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return commands

def add_sudo_command(command_text):
    """Adds a new sudo command to the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO sudo_commands (command_text) VALUES (?)", (command_text,))
    conn.commit()
    conn.close()

def delete_sudo_command(command_id):
    """Deletes a sudo command by its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sudo_commands WHERE id = ?", (command_id,))
    conn.commit()
    conn.close()

def get_high_risk_keywords():
    """Retrieves all high-risk keywords from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT keyword FROM high_risk_keywords")
    return [row[0] for row in cursor.fetchall()]

def get_interesting_keywords():
    """Retrieves all interesting keywords from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT keyword FROM interesting_keywords")
    return [row[0] for row in cursor.fetchall()]

def get_all_template_categories():
    """Retrieves all available vulnerability categories for the report generator."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT category FROM report_templates ORDER BY category")
    return [row[0] for row in cursor.fetchall()]

def get_report_template(category):
    """Retrieves the template text for a specific vulnerability category."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT template_text FROM report_templates WHERE category = ?", (category,))
    result = cursor.fetchone()
    return result[0] if result else ""

def get_all_templates():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM report_templates ORDER BY category")
    return [dict(row) for row in cursor.fetchall()]

def get_template_by_category(category):
    """Retrieves a single, structured template."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM report_templates WHERE category = ?", (category,))
    result = cursor.fetchone()
    return dict(result) if result else None

def add_template(category, desc, impact, validation, fix):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO report_templates (category, description, impact, validation_steps, fix_recommendation)
        VALUES (?, ?, ?, ?, ?)
    """, (category, desc, impact, validation, fix))
    conn.commit()
    conn.close()

def update_template(tpl_id, category, desc, impact, validation, fix):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE report_templates SET category=?, description=?, impact=?, validation_steps=?, fix_recommendation=?
        WHERE id = ?
    """, (category, desc, impact, validation, fix, tpl_id))
    conn.commit()
    conn.close()

def delete_template(template_id):
    """Deletes a report template by its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM report_templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()
