import sqlite3
import json

class DatabaseManager:
    """
    Manages SQLite database operations for storing and retrieving commands, themes, and command sequences.
    """
    def __init__(self, db_name="commands.db"):
        self.db_name = db_name
        self._create_tables()

    def _create_tables(self):
        """Creates the 'commands', 'themes', and 'command_sequences' tables if they don't exist."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                command TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS themes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                stylesheet TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS command_sequences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                sequence_json TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    # --- Command Management Methods ---
    def add_command(self, name, command_text):
        """Adds a new command to the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO commands (name, command) VALUES (?, ?)", (name, command_text))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Name already exists
        finally:
            conn.close()

    def get_commands(self):
        """Retrieves all commands from the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, command FROM commands ORDER BY name")
        commands = cursor.fetchall()
        conn.close()
        return commands

    def update_command(self, command_id, new_name, new_command_text):
        """Updates an existing command in the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE commands SET name = ?, command = ? WHERE id = ?",
                           (new_name, new_command_text, command_id))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # New name already exists
        finally:
            conn.close()

    def delete_command(self, command_id):
        """Deletes a command from the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM commands WHERE id = ?", (command_id,))
        conn.commit()
        conn.close()
        return True

    # --- Theme Management Methods ---
    def add_theme(self, name, stylesheet):
        """Adds a new theme to the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO themes (name, stylesheet) VALUES (?, ?)", (name, stylesheet))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Name already exists
        finally:
            conn.close()

    def get_themes(self):
        """Retrieves all themes from the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, stylesheet FROM themes ORDER BY name")
        themes = cursor.fetchall()
        conn.close()
        return themes

    def get_theme_by_name(self, name):
        """Retrieves a theme by its name."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, stylesheet FROM themes WHERE name = ?", (name,))
        theme = cursor.fetchone()
        conn.close()
        return theme

    def update_theme(self, theme_id, new_name, new_stylesheet):
        """Updates an existing theme in the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE themes SET name = ?, stylesheet = ? WHERE id = ?",
                           (new_name, new_stylesheet, theme_id))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # New name already exists
        finally:
            conn.close()

    def delete_theme(self, theme_id):
        """Deletes a theme from the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM themes WHERE id = ?", (theme_id,))
        conn.commit()
        conn.close()
        return True

    # --- Command Sequence Management Methods ---
    def add_sequence(self, name, sequence_data):
        """Adds a new command sequence to the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        try:
            sequence_json = json.dumps(sequence_data)
            cursor.execute("INSERT INTO command_sequences (name, sequence_json) VALUES (?, ?)", (name, sequence_json))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Name already exists
        finally:
            conn.close()

    def get_sequences(self):
        """Retrieves all command sequences from the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, sequence_json FROM command_sequences ORDER BY name")
        sequences = []
        for seq_id, name, seq_json in cursor.fetchall():
            sequences.append((seq_id, name, json.loads(seq_json)))
        conn.close()
        return sequences

    def update_sequence(self, sequence_id, new_name, new_sequence_data):
        """Updates an existing command sequence in the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        try:
            new_sequence_json = json.dumps(new_sequence_data)
            cursor.execute("UPDATE command_sequences SET name = ?, sequence_json = ? WHERE id = ?",
                           (new_name, new_sequence_json, sequence_id))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # New name already exists
        finally:
            conn.close()

    def delete_sequence(self, sequence_id):
        """Deletes a command sequence from the database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM command_sequences WHERE id = ?", (sequence_id,))
        conn.commit()
        conn.close()
        return True

    def delete_all_commands(self):
        dialog = ConfirmDialog(self, "Confirm Delete All", "Are you sure you want to delete ALL saved single commands? This action cannot be undone.")
        if dialog.exec_() == QMessageBox.Yes:
            self.db_manager.delete_all_commands()
            self.command_name_input.clear()
            self.command_text_input.clear()
            self.command_list.clearSelection()
            self.command_list.clearFocus()
            self.command_list.clear()
            self.statusBar().showMessage("All single commands have been deleted.")
