import sqlite3
import hashlib
from pathlib import Path
import threading

class Database:
    """Thread-safe SQLite database manager for the chat application.
    
    This class manages persistent storage of user accounts and chat messages using SQLite.
    It implements thread-safe database operations using thread-local storage and locks.
    
    Database Schema:
        users table:
            - id: Unique user identifier (PRIMARY KEY)
            - username: Unique username (TEXT)
            - password: Hashed password using SHA-256 (TEXT)
            
        messages table:
            - id: Unique message identifier (PRIMARY KEY)
            - sender: Username of message sender (FOREIGN KEY -> users.username)
            - recipient: Username of message recipient (FOREIGN KEY -> users.username)
            - content: Message content (TEXT)
            - timestamp: Message creation time (DATETIME)
    
    Thread Safety:
        - Uses thread-local storage for connections to prevent sharing between threads
        - Implements locks for write operations to prevent concurrent modifications
        - Each thread gets its own database connection and cursor
    """
    _instance = None
    _lock = threading.Lock()
    _local = threading.local()
    
    def __init__(self):
        self.db_path = Path('users.db')
        self._ensure_connection()
    
    def _ensure_connection(self):
        """Ensure the current thread has its own database connection.
        
        This method is called before any database operation to ensure thread safety.
        It creates a new connection if one doesn't exist for the current thread.
        The connection is stored in thread-local storage to prevent sharing.
        
        Thread Safety:
            Each thread gets its own connection stored in thread-local storage,
            preventing any cross-thread database access issues.
        """
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
        """Hash a password using SHA-256 for secure storage.
        
        Args:
            password (str): Plain text password to hash
            
        Returns:
            str: Hexadecimal string of hashed password
            
        Security:
            Uses SHA-256 for one-way hashing to prevent password recovery
            even if database is compromised.
        """
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username, password):
        """Register a new user account in the database.
        
        This method creates a new user account with the given username
        and a hashed version of the password. It prevents duplicate
        usernames and handles database errors gracefully.
        
        Args:
            username (str): Desired username for new account
            password (str): Plain text password to hash and store
            
        Returns:
            tuple: (success, message) where:
                - success (bool): True if registration successful
                - message (str): Success/error message
                
        Thread Safety:
            Uses a lock to prevent concurrent user creation
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