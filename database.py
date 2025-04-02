import sqlite3
import hashlib
from pathlib import Path
import threading

class Database:
    """Thread-safe SQLite database manager for chat application.
    
    Manages user accounts and chat messages using SQLite with thread-safe operations.
    Uses thread-local storage for connections and locks for write operations.
    
    Schema:
        users: id (PK), username (unique), password (hashed)
        messages: id (PK), sender, recipient, content, timestamp
    """
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
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        
        self._local.cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender) REFERENCES users (username),
                FOREIGN KEY (recipient) REFERENCES users (username)
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

    def close(self):
        """Close the database connection"""
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None
            self._local.cursor = None