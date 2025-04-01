import sqlite3
import hashlib
from pathlib import Path

class Database:
    def __init__(self):
        self.db_path = Path('users.db')
        self.conn = None
        self.cursor = None
        self.setup()
    
    def setup(self):
        """Initialize database connection and create tables if they don't exist"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Create users table if it doesn't exist
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        self.conn.commit()
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username, password):
        """Register a new user"""
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            self.conn.commit()
            return True, "Registration successful"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, str(e)
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, hashed_password)
            )
            user = self.cursor.fetchone()
            return user is not None, "Login successful" if user else "Invalid credentials"
        except Exception as e:
            return False, str(e)
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()