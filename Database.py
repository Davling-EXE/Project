import sqlite3
from Protocol import hash_password, verify_password

class Database:
    def __init__(self, db_file="chat_app.db"):
        self.db_file = db_file
        self.conn = None
        self.initialize_db()
        
    def connect(self):
        """Connect to the SQLite database"""
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        return self.conn.cursor()
        
    def initialize_db(self):
        """Create database tables if they don't exist"""
        cursor = self.connect()
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create groups table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
        ''')
        
        # Create group_members table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER,
            user_id INTEGER,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create messages table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            recipient_id INTEGER,
            group_id INTEGER,
            content TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (recipient_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id)
        )
        ''')
        
        self.conn.commit()
        
    def register_user(self, username, password, public_key=None):
        """Register a new user"""
        cursor = self.connect()
        try:
            hashed_password = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)",
                (username, hashed_password, public_key)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Username already exists
            return False
            
    def authenticate_user(self, username, password):
        """Authenticate a user"""
        cursor = self.connect()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and verify_password(user['password'], password):
            return dict(user)
        return None
        
    def update_user_key(self, username, public_key):
        """Update a user's public key"""
        cursor = self.connect()
        cursor.execute(
            "UPDATE users SET public_key = ? WHERE username = ?",
            (public_key, username)
        )
        self.conn.commit()
        
    def get_user_by_username(self, username):
        """Get user details by username"""
        cursor = self.connect()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        return dict(user) if user else None
        
    def get_all_users(self):
        """Get all users"""
        cursor = self.connect()
        cursor.execute("SELECT id, username, last_seen FROM users")
        return [dict(user) for user in cursor.fetchall()]
        
    def create_group(self, name, created_by_username):
        """Create a new group"""
        cursor = self.connect()
        user = self.get_user_by_username(created_by_username)
        
        if not user:
            return None
            
        cursor.execute(
            "INSERT INTO groups (name, created_by) VALUES (?, ?)",
            (name, user['id'])
        )
        self.conn.commit()
        
        group_id = cursor.lastrowid
        
        # Add creator as a member
        self.add_user_to_group(group_id, user['id'])
        
        return group_id
        
    def add_user_to_group(self, group_id, user_id):
        """Add a user to a group"""
        cursor = self.connect()
        try:
            cursor.execute(
                "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
                (group_id, user_id)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # User is already in the group
            return False
            
    def remove_user_from_group(self, group_id, user_id):
        """Remove a user from a group"""
        cursor = self.connect()
        cursor.execute(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id)
        )
        self.conn.commit()
        return cursor.rowcount > 0
        
    def get_user_groups(self, username):
        """Get all groups a user is a member of"""
        cursor = self.connect()
        user = self.get_user_by_username(username)
        
        if not user:
            return []
            
        cursor.execute("""
            SELECT g.* FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = ?
        """, (user['id'],))
        
        return [dict(group) for group in cursor.fetchall()]
        
    def get_group_members(self, group_id):
        """Get all members of a group"""
        cursor = self.connect()
        cursor.execute("""
            SELECT u.id, u.username FROM users u
            JOIN group_members gm ON u.id = gm.user_id
            WHERE gm.group_id = ?
        """, (group_id,))
        
        return [dict(user) for user in cursor.fetchall()]
        
    def save_message(self, sender_username, recipient_username=None, group_id=None, content=None):
        """Save a message to the database"""
        cursor = self.connect()
        sender = self.get_user_by_username(sender_username)
        
        if not sender:
            return False
            
        recipient_id = None
        if recipient_username:
            recipient = self.get_user_by_username(recipient_username)
            if recipient:
                recipient_id = recipient['id']
                
        cursor.execute(
            "INSERT INTO messages (sender_id, recipient_id, group_id, content) VALUES (?, ?, ?, ?)",
            (sender['id'], recipient_id, group_id, content)
        )
        self.conn.commit()
        return cursor.lastrowid
        
    def get_private_messages(self, user1_username, user2_username, limit=50):
        """Get private messages between two users"""
        cursor = self.connect()
        user1 = self.get_user_by_username(user1_username)
        user2 = self.get_user_by_username(user2_username)
        
        if not user1 or not user2:
            return []
            
        cursor.execute("""
            SELECT m.*, u.username as sender_username FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
            ORDER BY m.sent_at DESC LIMIT ?
        """, (user1['id'], user2['id'], user2['id'], user1['id'], limit))
        
        messages = [dict(msg) for msg in cursor.fetchall()]
        messages.reverse()  # Show oldest messages first
        return messages
        
    def get_group_messages(self, group_id, limit=50):
        """Get messages from a group"""
        cursor = self.connect()
        cursor.execute("""
            SELECT m.*, u.username as sender_username FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.group_id = ?
            ORDER BY m.sent_at DESC LIMIT ?
        """, (group_id, limit))
        
        messages = [dict(msg) for msg in cursor.fetchall()]
        messages.reverse()  # Show oldest messages first
        return messages
        
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()