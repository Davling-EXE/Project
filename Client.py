
from tkinter import *
import socket
from Protocol import *
from tkinter import messagebox
import threading
from tkinter.scrolledtext import ScrolledText
from database import Database

"""
Chat Client Application

This module implements a GUI-based chat client using Tkinter. It provides functionality for:
- User authentication (login/register)
- Real-time messaging between users
- Persistent chat history
- Contact list management

The client connects to a chat server and uses a custom protocol for communication.
It supports private messaging between users and maintains chat history in a database.
"""

# Network configuration constants
SERVER_IP = "127.0.0.1"  # Local server address
PORT = 8820             # Server port number
MAX_PACKAGE = 1024      # Maximum packet size for network communication

# Initialize main Tkinter root window
ROOT = Tk()
ROOT.title("Chat Login")


class Client:

    def __init__(self):
        """Initialize the chat client with necessary attributes.
        
        Attributes:
            server: Socket connection to chat server
            user_box: Listbox widget displaying online users
            top: Top-level window reference
            name_input: Username entry widget
            pass_input: Password entry widget
            username: Current user's username
            chat_windows: Dictionary mapping usernames to chat window instances
            main_window: Main application window
            db: Database instance for persistent storage
        """
        self.server = None          # Socket connection to server
        self.user_box = None       # Listbox for displaying online users
        self.top = None            # Reference to top-level window
        self.name_input = None     # Username input field
        self.pass_input = None     # Password input field
        self.username = ""         # Current user's username
        self.chat_windows = {}     # Active chat windows {username: ChatWindow}
        self.main_window = None    # Main application window
        self.db = Database()       # Database connection

    def get_window_position(self, width, height):
        """Calculate window position to center it on screen.
        
        Args:
            width (int): Desired window width in pixels
            height (int): Desired window height in pixels
            
        Returns:
            str: Tkinter geometry string in format 'widthxheight+x+y'
                where x,y are screen coordinates for centered position
        """
        screen_width = ROOT.winfo_screenwidth()     # Get screen width
        screen_height = ROOT.winfo_screenheight()  # Get screen height
        x = (screen_width - width) // 2           # Calculate x coordinate
        y = (screen_height - height) // 2         # Calculate y coordinate
        return f"{width}x{height}+{x}+{y}"         # Return geometry string

    def connect(self, is_login=True):
        """Handle user authentication and establish server connection.
        
        This method performs the following steps:
        1. Validates user input (username/password)
        2. Authenticates with database (login or register)
        3. Establishes socket connection with chat server
        4. Processes server response
        
        Args:
            is_login (bool): True for login, False for registration
            
        Side effects:
            - Updates self.username if authentication succeeds
            - Creates socket connection in self.server
            - Shows error messages for failed attempts
            - Opens main chat window on success
        """
        try:
            username = self.name_input.get()
            password = self.pass_input.get()
            
            if not username or not password:
                messagebox.showerror("Error", "Please enter both username and password")
                return

            if is_login:
                success, message = self.db.authenticate_user(username, password)
            else:
                success, message = self.db.register_user(username, password)

            if not success:
                messagebox.showerror("Authentication Error", message)
                return

            self.username = username
            self.server = socket.socket()
            self.server.connect((SERVER_IP, PORT))
            self.server.send(create_msg("connect", self.username, "server", "").encode())

            msg_type, sender, recipient, content = parse_msg(self.server)
            if msg_type == "error":
                messagebox.showerror("Connection Error", content)
                self.server.close()
                return

            messagebox.showinfo("Connected successfully", f"Connected as {self.username}")
            self.open_chat()

        except socket.error as err:
            messagebox.showerror("Connection Error", str(err))

    def receive(self):
        """Handle incoming messages from the server in a separate thread.
        
        This method runs in a background thread and continuously processes
        different types of messages:
        - error: Display error messages and handle disconnection
        - user_list: Update the online users list
        - message: Display incoming chat messages
        - connect: Show server connection messages
        
        The method handles socket errors and updates UI accordingly.
        Runs until the connection is closed or an error occurs.
        """
        while True:
            try:
                msg_type, sender, recipient, content = parse_msg(self.server)
                
                if msg_type == "error":
                    messagebox.showerror("Error", content)
                    if hasattr(self, 'top') and self.top:
                        self.top.destroy()
                    break
                elif msg_type == "user_list":
                    try:
                        if self.user_box and self.user_box.winfo_exists():
                            users = content.split(",")
                            self.user_box.delete(0, END)
                            for user in users:
                                if user != self.username:
                                    self.user_box.insert(END, user)
                    except TclError:
                        # Widget was destroyed, ignore the error
                        pass
                elif msg_type == "message":
                    try:
                        if sender not in self.chat_windows:
                            self.open_chat_window(sender)
                        if sender in self.chat_windows and self.chat_windows[sender].window.winfo_exists():
                            self.chat_windows[sender].add_message(f"{sender}: {content}\n")
                    except TclError:
                        # Chat window was destroyed, remove it from chat_windows
                        if sender in self.chat_windows:
                            del self.chat_windows[sender]
                elif msg_type == "connect" and sender == "server":
                    messagebox.showinfo("Server Message", content)

            except socket.error as err:
                messagebox.showerror("Error", str(err))
                self.server.close()
                if hasattr(self, 'top') and self.top:
                    self.top.destroy()
                break

    def write(self, recipient, message):
        """Send a chat message to a specific recipient.
        
        Args:
            recipient (str): Username of the message recipient
            message (str): Content of the message to send
            
        Side effects:
            - Sends message to server via socket
            - Updates local chat window with sent message
        """
        if recipient and message:
            self.server.send(create_msg("message", self.username, recipient, message).encode())
            if recipient in self.chat_windows:
                self.chat_windows[recipient].add_message(f"Me: {message}\n")

    def exit_chat(self):
        """Clean up resources and exit the chat application.
        
        This method performs a graceful shutdown by:
        1. Sending disconnect message to server
        2. Closing all chat windows
        3. Closing the main window
        4. Terminating the program
        
        Handles any errors during cleanup and ensures proper exit.
        """
        try:
            # Send disconnect message to server
            if self.server:
                self.server.send(create_msg("disconnect", self.username, "server", "").encode())
                self.server.close()

            # Close all chat windows
            for window in self.chat_windows.values():
                if window.window.winfo_exists():
                    window.window.destroy()
            
            # Close main window if it exists
            if self.main_window and self.main_window.winfo_exists():
                self.main_window.destroy()
            
            # Close root window and exit program
            ROOT.quit()
            ROOT.destroy()
            import sys
            sys.exit(0)
        except Exception as e:
            messagebox.showerror("Error", f"Error while closing: {str(e)}")
            sys.exit(1)

    class ChatWindow:
        """Represents a private chat window between two users.
        
        This class manages the UI and functionality of individual chat windows,
        including message display, sending messages, and window management.
        """
        
        def __init__(self, parent, username, recipient, write_callback):
            """Initialize a new chat window.
            
            Args:
                parent (Client): Reference to main client instance
                username (str): Current user's username
                recipient (str): Chat partner's username
                write_callback (callable): Function to send messages
            """
            self.parent = parent
            self.window = Toplevel()
            self.window.title(f"Chat with {recipient}")
            self.window.geometry(parent.get_window_position(500, 600))
            self.window.minsize(400, 500)
            self.recipient = recipient
            self.write_callback = write_callback

            # Configure window close protocol
            self.window.protocol("WM_DELETE_WINDOW", self.exit_chat)

            # Top frame for buttons
            top_frame = Frame(self.window)
            top_frame.pack(fill=X, padx=15, pady=10)
            
            exit_button = Button(top_frame, text="Close Chat", font=('Segoe UI', '10'),
                                command=self.exit_chat)
            exit_button.pack(side=RIGHT)

            # Chat display area
            self.chat_box = ScrolledText(self.window, font=('Segoe UI', '10'), bd=2)
            self.chat_box.pack(fill=BOTH, expand=True, padx=15, pady=10)

            # Input area
            bottom_frame = Frame(self.window)
            bottom_frame.pack(fill=X, padx=15, pady=(0, 15))
            
            self.send_input = Entry(bottom_frame, font=('Segoe UI', '10'), bd=2)
            self.send_input.pack(side=LEFT, expand=True, fill=X, padx=(0, 10))
            self.send_input.bind('<Return>', self.send_message)
            
            send_button = Button(bottom_frame, text="Send", font=('Segoe UI', '10'),
                                command=self.send_message)
            send_button.pack(side=RIGHT)

        def send_message(self, event=None):
            message = self.send_input.get()
            if message:
                self.write_callback(self.recipient, message)
                self.send_input.delete(0, END)

        def add_message(self, message):
            self.chat_box.insert(END, message)
            self.chat_box.see(END)
            
        def exit_chat(self):
            """Closes the chat window and removes it from the parent's chat_windows dictionary"""
            if self.recipient in self.parent.chat_windows:
                del self.parent.chat_windows[self.recipient]
            self.window.destroy()

    def open_chat_window(self, recipient):
        if recipient not in self.chat_windows:
            self.chat_windows[recipient] = self.ChatWindow(self, self.username, recipient, self.write)
            # Load chat history
            chat_history = self.db.get_chat_history(self.username, recipient)
            for sender, content, timestamp in chat_history:
                display_name = "Me" if sender == self.username else sender
                self.chat_windows[recipient].add_message(f"{display_name} ({timestamp}): {content}\n")

    def open_chat(self):
        """
        opens the main chat window with contacts list
        :return:
        """
        self.main_window = Toplevel()
        self.main_window.title(f"Contacts - {self.username}")
        self.main_window.geometry(self.get_window_position(350, 500))
        self.main_window.minsize(300, 400)

        # Configure window close protocol
        self.main_window.protocol("WM_DELETE_WINDOW", self.exit_chat)

        # Contacts list
        Label(self.main_window, text="Online Users", font=('Segoe UI', '12', 'bold')).pack(pady=10)
        self.user_box = Listbox(self.main_window, font=('Segoe UI', '10'), bd=2)
        self.user_box.pack(fill=BOTH, expand=True, padx=15, pady=(0, 10))
        self.user_box.bind('<Double-Button-1>', lambda e: self.open_chat_window(self.user_box.get(ACTIVE)))

        # Exit button
        exit_button = Button(self.main_window, text="Exit Chat", font=('Segoe UI', '11'),
                            command=self.exit_chat)
        exit_button.pack(pady=15)

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

    def main(self):
        """Initialize and run the main application.
        
        Creates the login/register window with input fields and buttons.
        Sets up the main event loop for the application.
        """
        # Create login/register window
        ROOT.geometry(self.get_window_position(300, 250))
        ROOT.minsize(250, 250)
        frame = Frame(ROOT, padx=20, pady=20)
        frame.pack(expand=True, fill=BOTH)

        instruction_label = Label(frame, text="Welcome to Chat",
                               font=('Segoe UI', '11', 'bold'))
        instruction_label.pack(pady=10)

        Label(frame, text="Username:", font=('Segoe UI', '10')).pack(anchor=W)
        self.name_input = Entry(frame, font=('Segoe UI', '11'))
        self.name_input.pack(fill=X, pady=(0, 10))

        Label(frame, text="Password:", font=('Segoe UI', '10')).pack(anchor=W)
        self.pass_input = Entry(frame, font=('Segoe UI', '11'), show='*')
        self.pass_input.pack(fill=X, pady=(0, 15))

        button_frame = Frame(frame)
        button_frame.pack(fill=X)

        login_button = Button(button_frame, text="Login", command=lambda: self.connect(True),
                           font=('Segoe UI', '11'), bg='#4CAF50', fg='white',
                           width=12)
        login_button.pack(side=LEFT, padx=5)

        register_button = Button(button_frame, text="Register", command=lambda: self.connect(False),
                              font=('Segoe UI', '11'), bg='#2196F3', fg='white',
                              width=12)
        register_button.pack(side=RIGHT, padx=5)

        ROOT.mainloop()


if __name__ == '__main__':
    Client = Client()
    Client.main()
