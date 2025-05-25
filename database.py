import sqlite3
import hashlib
from pathlib import Path
import threading


class Database:
    _instance = None
    _lock = threading.Lock()
    _local = threading.local()

    def __init__(self):
        self.db_path = Path('users.db')
        self._ensure_connection()

    def _ensure_connection(self):
        """Creates thread-local database connection if none exists."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.cursor = self._local.conn.cursor()
            self._setup_tables()

    def _setup_tables(self):
        """Initialize database tables if they don't exist"""
        self._local.cursor.execute("""
                                   CREATE TABLE IF NOT EXISTS users
                                   (
                                       id
                                       INTEGER
                                       PRIMARY
                                       KEY
                                       AUTOINCREMENT,
                                       username
                                       TEXT
                                       UNIQUE
                                       NOT
                                       NULL,
                                       password
                                       TEXT
                                       NOT
                                       NULL
                                   )
                                   """)

        self._local.cursor.execute("""
                                   CREATE TABLE IF NOT EXISTS messages
                                   (
                                       id
                                       INTEGER
                                       PRIMARY
                                       KEY
                                       AUTOINCREMENT,
                                       sender
                                       TEXT
                                       NOT
                                       NULL,
                                       recipient
                                       TEXT
                                       NOT
                                       NULL,
                                       content
                                       TEXT
                                       NOT
                                       NULL,
                                       timestamp
                                       DATETIME
                                       DEFAULT
                                       CURRENT_TIMESTAMP,
                                       FOREIGN
                                       KEY
                                   (
                                       sender
                                   ) REFERENCES users
                                   (
                                       username
                                   ),
                                       FOREIGN KEY
                                   (
                                       recipient
                                   ) REFERENCES users
                                   (
                                       username
                                   )
                                       )
                                   """)

        self._local.cursor.execute("""
                                   CREATE TABLE IF NOT EXISTS groups
                                   (
                                       id
                                       INTEGER
                                       PRIMARY
                                       KEY
                                       AUTOINCREMENT,
                                       group_name
                                       TEXT
                                       UNIQUE
                                       NOT
                                       NULL,
                                       created_by
                                       TEXT
                                       NOT
                                       NULL,
                                       created_at
                                       DATETIME
                                       DEFAULT
                                       CURRENT_TIMESTAMP,
                                       FOREIGN
                                       KEY
                                   (
                                       created_by
                                   ) REFERENCES users
                                   (
                                       username
                                   )
                                   )
                                   """)

        self._local.cursor.execute("""
                                   CREATE TABLE IF NOT EXISTS group_members
                                   (
                                       id
                                       INTEGER
                                       PRIMARY
                                       KEY
                                       AUTOINCREMENT,
                                       group_name
                                       TEXT
                                       NOT
                                       NULL,
                                       username
                                       TEXT
                                       NOT
                                       NULL,
                                       joined_at
                                       DATETIME
                                       DEFAULT
                                       CURRENT_TIMESTAMP,
                                       FOREIGN
                                       KEY
                                   (
                                       group_name
                                   ) REFERENCES groups
                                   (
                                       group_name
                                   ),
                                       FOREIGN KEY
                                   (
                                       username
                                   ) REFERENCES users
                                   (
                                       username
                                   ),
                                       UNIQUE
                                   (
                                       group_name,
                                       username
                                   )
                                   )
                                   """)

        self._local.cursor.execute("""
                                   CREATE TABLE IF NOT EXISTS group_messages
                                   (
                                       id
                                       INTEGER
                                       PRIMARY
                                       KEY
                                       AUTOINCREMENT,
                                       group_name
                                       TEXT
                                       NOT
                                       NULL,
                                       sender
                                       TEXT
                                       NOT
                                       NULL,
                                       content
                                       TEXT
                                       NOT
                                       NULL,
                                       timestamp
                                       DATETIME
                                       DEFAULT
                                       CURRENT_TIMESTAMP,
                                       FOREIGN
                                       KEY
                                   (
                                       group_name
                                   ) REFERENCES groups
                                   (
                                       group_name
                                   ),
                                       FOREIGN KEY
                                   (
                                       sender
                                   ) REFERENCES users
                                   (
                                       username
                                   )
                                   )
                                   """)
        self._local.conn.commit()

    def hash_password(self, password):
        """Hash password using SHA-256.

        Args:
            password: Plain text password

        Returns:
            Hexadecimal string of hashed password
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password):
        """Register a new user account.

        Args:
            username: Desired username
            password: Plain text password

        Returns:
            (success, message) tuple
        """
        self._ensure_connection()
        try:
            hashed_password = self.hash_password(password)
            with self._lock:
                self._local.cursor.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_password)
                )
                self._local.conn.commit()
            return True, "Registration successful"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, str(e)

    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        self._ensure_connection()
        try:
            hashed_password = self.hash_password(password)
            self._local.cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, hashed_password)
            )
            user = self._local.cursor.fetchone()
            return user is not None, "Login successful" if user else "Invalid credentials"
        except Exception as e:
            return False, str(e)

    def save_message(self, sender, recipient, content):
        """Save a message to the database"""
        self._ensure_connection()
        try:
            with self._lock:
                self._local.cursor.execute(
                    "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)",
                    (sender, recipient, content)
                )
                self._local.conn.commit()
            return True
        except Exception as e:
            print(f"Error saving message: {e}")
            return False

    def get_chat_history(self, user1, user2):
        """Get chat history between two users"""
        self._ensure_connection()
        try:
            self._local.cursor.execute(
                """SELECT sender, content, timestamp
                   FROM messages
                   WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                   ORDER BY timestamp ASC""",
                (user1, user2, user2, user1)
            )
            return self._local.cursor.fetchall()
        except Exception as e:
            print(f"Error retrieving chat history: {e}")
            return []

    def create_group(self, group_name, creator):
        """Create a new group"""
        self._ensure_connection()
        try:
            with self._lock:
                self._local.cursor.execute(
                    "INSERT INTO groups (group_name, created_by) VALUES (?, ?)",
                    (group_name, creator)
                )
                # Add creator as first member
                self._local.cursor.execute(
                    "INSERT INTO group_members (group_name, username) VALUES (?, ?)",
                    (group_name, creator)
                )
                self._local.conn.commit()
            return True, "Group created successfully"
        except sqlite3.IntegrityError:
            return False, "Group name already exists"
        except Exception as e:
            return False, str(e)

    def join_group(self, group_name, username):
        """Join an existing group"""
        self._ensure_connection()
        try:
            # Check if group exists
            self._local.cursor.execute(
                "SELECT * FROM groups WHERE group_name = ?",
                (group_name,)
            )
            if not self._local.cursor.fetchone():
                return False, "Group does not exist"
            
            with self._lock:
                self._local.cursor.execute(
                    "INSERT INTO group_members (group_name, username) VALUES (?, ?)",
                    (group_name, username)
                )
                self._local.conn.commit()
            return True, "Joined group successfully"
        except sqlite3.IntegrityError:
            return False, "Already a member of this group"
        except Exception as e:
            return False, str(e)

    def get_user_groups(self, username):
        """Get all groups a user is a member of"""
        self._ensure_connection()
        try:
            self._local.cursor.execute(
                "SELECT group_name FROM group_members WHERE username = ?",
                (username,)
            )
            return [row[0] for row in self._local.cursor.fetchall()]
        except Exception as e:
            print(f"Error retrieving user groups: {e}")
            return []

    def get_group_members(self, group_name):
        """Get all members of a group"""
        self._ensure_connection()
        try:
            self._local.cursor.execute(
                "SELECT username FROM group_members WHERE group_name = ?",
                (group_name,)
            )
            return [row[0] for row in self._local.cursor.fetchall()]
        except Exception as e:
            print(f"Error retrieving group members: {e}")
            return []

    def save_group_message(self, group_name, sender, content):
        """Save a group message to the database"""
        self._ensure_connection()
        try:
            with self._lock:
                self._local.cursor.execute(
                    "INSERT INTO group_messages (group_name, sender, content) VALUES (?, ?, ?)",
                    (group_name, sender, content)
                )
                self._local.conn.commit()
            return True
        except Exception as e:
            print(f"Error saving group message: {e}")
            return False

    def get_group_chat_history(self, group_name):
        """Get chat history for a group"""
        self._ensure_connection()
        try:
            self._local.cursor.execute(
                "SELECT sender, content, timestamp FROM group_messages WHERE group_name = ? ORDER BY timestamp ASC",
                (group_name,)
            )
            return self._local.cursor.fetchall()
        except Exception as e:
            print(f"Error retrieving group chat history: {e}")
            return []

    def close(self):
        """Close the database connection"""
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None
            self._local.cursor = None