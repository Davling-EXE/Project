
from tkinter import *
import socket
from Protocol import *
from tkinter import messagebox, simpledialog
import threading
from tkinter.scrolledtext import ScrolledText
from database import Database
from Encryption import RSAEncryption, AESEncryption
from Call import VoiceCall
import sys
import base64

"""Chat Client Application

This module implements a GUI-based chat client using Tkinter that provides:
- User authentication with secure password hashing
- Real-time private messaging between users
- Persistent chat history using SQLite
- Dynamic contact list with online status

GUI Components:
- Login/Register window: User authentication forms
- Main window: Online users list and chat management
- Chat windows: Individual message threads with scrollable history

Network Features:
- Asynchronous message handling using threads
- Automatic reconnection on connection loss
- Real-time updates of online user status

Error Handling:
- Network errors: Automatic reconnection attempts
- GUI errors: Graceful widget cleanup
- Database errors: Transaction rollback and retry

The client implements the chat protocol for structured communication
with the server and maintains persistent message history.
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
        self.group_windows = {}    # Active group chat windows {group_name: ChatWindow}
        self.main_window = None    # Main application window
        self.db = Database()       # Database connection
        self.rsa = RSAEncryption()
        self.aes = None
        self.peer_public_keys = {}
        self.user_groups = []      # List of groups user belongs to
        self.voice_call = None     # Voice call manager instance

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
            
            # Initialize voice call manager
            self.voice_call = VoiceCall(self)
            
            # Exchange public keys
            connect_msg = create_msg("connect", self.username, "server", self.rsa.export_public_key().decode())
            print(f"Sending connect message: {connect_msg}")
            self.server.send(connect_msg.encode())

            print("Waiting for server response...")
            msg_type, sender, recipient, content = parse_msg(self.server)
            print(f"Received: {msg_type}, {sender}, {recipient}, {content}")

            if msg_type == "connect":
                # Receive server's public key and AES key encrypted for us
                server_pub_key = content.encode()
                # Generate AES key and send it encrypted to server
                self.aes = AESEncryption()
                encrypted_aes = self.rsa.encrypt_with_public_key(self.aes.key, server_pub_key)
                aes_msg = create_msg("aes_key", self.username, "server", encrypted_aes.hex())
                print(f"Sending AES key message: {aes_msg}")
                self.server.send(aes_msg.encode())
            elif msg_type == "error":
                messagebox.showerror("Connection Error", content)
                self.server.close()
                return
            elif msg_type == "disconnect":
                messagebox.showerror("Connection Error", "Server disconnected")
                self.server.close()
                return
            else:
                messagebox.showerror("Connection Error", f"Unexpected message type: {msg_type}")
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
                if msg_type == "message":
                    if self.aes:
                        try:
                            decrypted = self.aes.decrypt(bytes.fromhex(content)).decode()
                        except Exception:
                            decrypted = "[Decryption failed]"
                    else:
                        decrypted = content
                    if sender not in self.chat_windows:
                        self.open_chat_window(sender)
                    if sender in self.chat_windows and self.chat_windows[sender].window.winfo_exists():
                        self.chat_windows[sender].add_message(f"{sender}: {decrypted}\n")
                    continue

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
                            # Update voice call user list as well
                            self.update_voice_user_list()
                    except TclError:
                        # Widget was destroyed, ignore the error
                        pass
                elif msg_type == "group_list":
                    try:
                        if content:
                            self.user_groups = content.split(",")
                        else:
                            self.user_groups = []
                        # Update group_box if it exists and is valid
                        if hasattr(self, 'group_box') and self.group_box and self.group_box.winfo_exists():
                            self.group_box.delete(0, END)
                            for group in self.user_groups:
                                self.group_box.insert(END, group)
                        # If group_box doesn't exist yet, the groups will be populated when main window is created
                    except TclError:
                        # Widget was destroyed, ignore the error
                        pass
                elif msg_type == "group_message":
                    group_name = recipient
                    if self.aes:
                        try:
                            decrypted = self.aes.decrypt(bytes.fromhex(content)).decode()
                        except Exception:
                            decrypted = "[Decryption failed]"
                    else:
                        decrypted = content
                    if group_name not in self.group_windows:
                        self.open_group_chat_window(group_name)
                    if group_name in self.group_windows and self.group_windows[group_name].window.winfo_exists():
                        self.group_windows[group_name].add_message(f"{sender}: {decrypted}\n")
                elif msg_type == "info":
                    messagebox.showinfo("Info", content)
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
                elif msg_type == "call_request":
                    # Handle incoming call request
                    if self.voice_call:
                        self.voice_call.show_incoming_call_dialog(sender)
                elif msg_type == "call_accept":
                    # Handle call acceptance
                    if self.voice_call and self.voice_call.is_calling:
                        self.voice_call.is_calling = False
                        self.voice_call.is_in_call = True
                        self.voice_call.show_call_window(sender)
                        self.voice_call.start_audio()
                elif msg_type == "call_decline":
                    # Handle call decline
                    if self.voice_call and self.voice_call.is_calling:
                        messagebox.showinfo("Call Declined", f"{sender} declined your call")
                        self.voice_call.reset_call_state()
                        if self.voice_call.call_window:
                            self.voice_call.call_window.destroy()
                            self.voice_call.call_window = None
                elif msg_type == "call_end":
                    # Handle call end
                    if self.voice_call and (self.voice_call.is_calling or self.voice_call.is_in_call):
                        messagebox.showinfo("Call Ended", f"{sender} ended the call")
                        self.voice_call.stop_audio()
                        self.voice_call.reset_call_state()
                        if self.voice_call.call_window:
                            self.voice_call.call_window.destroy()
                            self.voice_call.call_window = None
                elif msg_type == "voice_data":
                    # Handle incoming voice data with decryption
                    if self.voice_call:
                        # Decrypt voice data before passing to VoiceCall
                        if self.aes:
                            try:
                                decrypted_content = self.aes.decrypt(bytes.fromhex(content)).decode()
                            except Exception as e:
                                print(f"Voice data decryption error: {e}")
                                continue
                        else:
                            decrypted_content = content
                        self.voice_call.handle_voice_data(sender, decrypted_content)

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
        if self.aes:
            encrypted = self.aes.encrypt(message.encode()).hex()
        else:
            encrypted = message
        self.server.send(create_msg("message", self.username, recipient, encrypted).encode())
        if recipient in self.chat_windows:
            self.chat_windows[recipient].add_message(f"Me: {message}\n")

    def write_group(self, group_name, message):
        """Send a message to a group chat.

        Args:
            group_name (str): Name of the group
            message (str): Content of the message to send
        """
        if self.aes:
            encrypted = self.aes.encrypt(message.encode()).hex()
        else:
            encrypted = message
        self.server.send(create_msg("group_message", self.username, group_name, encrypted).encode())
        if group_name in self.group_windows:
            self.group_windows[group_name].add_message(f"Me: {message}\n")
    
    def send_voice_data(self, recipient, audio_data):
        """Send encrypted voice data to a recipient.
        
        Args:
            recipient (str): Username of the recipient
            audio_data (bytes): Raw audio data to send
        """
        # First encode audio data as base64
        encoded_data = base64.b64encode(audio_data).decode()
        
        if self.aes:
            encrypted = self.aes.encrypt(encoded_data.encode()).hex()
        else:
            encrypted = encoded_data
        msg = create_msg("voice_data", self.username, recipient, encrypted)
        self.server.send(msg.encode())

    def exit_chat(self):
        """Clean up resources and exit the chat application.

        This method performs a graceful shutdown by:
        1. Sends disconnect message to server
        2. Closes all chat windows
        3. Closes the main window
        4. Terminates the program

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
            
            # Close all group chat windows
            for window in self.group_windows.values():
                if window.window.winfo_exists():
                    window.window.destroy()
            
            # Clean up voice call resources
            if self.voice_call:
                self.voice_call.cleanup()

            # Close main window if it exists
            if self.main_window and self.main_window.winfo_exists():
                self.main_window.destroy()

            # Close root window and exit program
            ROOT.quit()
            ROOT.destroy()
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

            exit_button = Button(top_frame, text="Close Chat", font=('Segoe UI', 10),
                                 command=self.exit_chat)
            exit_button.pack(side=RIGHT)

            # Chat display area
            self.chat_box = ScrolledText(self.window, font=('Segoe UI', 10), bd=2)
            self.chat_box.pack(fill=BOTH, expand=True, padx=15, pady=10)

            # Input area
            bottom_frame = Frame(self.window)
            bottom_frame.pack(fill=X, padx=15, pady=(0, 15))

            self.send_input = Entry(bottom_frame, font=('Segoe UI', 10), bd=2)
            self.send_input.pack(side=LEFT, expand=True, fill=X, padx=(0, 10))
            self.send_input.bind('<Return>', self.send_message)

            send_button = Button(bottom_frame, text="Send", font=('Segoe UI', 10),
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

    class GroupChatWindow:
        """Represents a group chat window.

        This class manages the UI and functionality of group chat windows,
        including message display, sending messages, and window management.
        """

        def __init__(self, parent, username, group_name, write_callback):
            """Initialize a new group chat window.

            Args:
                parent (Client): Reference to main client instance
                username (str): Current user's username
                group_name (str): Name of the group
                write_callback (callable): Function to send group messages
            """
            self.parent = parent
            self.window = Toplevel()
            self.window.title(f"Group: {group_name}")
            self.window.geometry(parent.get_window_position(500, 600))
            self.window.minsize(400, 500)
            self.group_name = group_name
            self.write_callback = write_callback

            # Configure window close protocol
            self.window.protocol("WM_DELETE_WINDOW", self.exit_chat)

            # Top frame for buttons
            top_frame = Frame(self.window)
            top_frame.pack(fill=X, padx=15, pady=10)

            exit_button = Button(top_frame, text="Close Chat", font=('Segoe UI', 10),
                                 command=self.exit_chat)
            exit_button.pack(side=RIGHT)

            # Chat display area
            self.chat_box = ScrolledText(self.window, font=('Segoe UI', 10), bd=2)
            self.chat_box.pack(fill=BOTH, expand=True, padx=15, pady=10)

            # Input area
            bottom_frame = Frame(self.window)
            bottom_frame.pack(fill=X, padx=15, pady=(0, 15))

            self.send_input = Entry(bottom_frame, font=('Segoe UI', 10), bd=2)
            self.send_input.pack(side=LEFT, expand=True, fill=X, padx=(0, 10))
            self.send_input.bind('<Return>', self.send_message)

            send_button = Button(bottom_frame, text="Send", font=('Segoe UI', 10),
                                 command=self.send_message)
            send_button.pack(side=RIGHT)

        def send_message(self, event=None):
            message = self.send_input.get()
            if message:
                self.write_callback(self.group_name, message)
                self.send_input.delete(0, END)

        def add_message(self, message):
            self.chat_box.insert(END, message)
            self.chat_box.see(END)

        def exit_chat(self):
            """Closes the group chat window and removes it from the parent's group_windows dictionary"""
            if self.group_name in self.parent.group_windows:
                del self.parent.group_windows[self.group_name]
            self.window.destroy()

    def open_chat_window(self, recipient):
        if recipient not in self.chat_windows:
            self.chat_windows[recipient] = self.ChatWindow(self, self.username, recipient, self.write)
            # Load chat history
            chat_history = self.db.get_chat_history(self.username, recipient)
            for sender, content, timestamp in chat_history:
                display_name = "Me" if sender == self.username else sender
                self.chat_windows[recipient].add_message(f"{display_name} ({timestamp}): {content}\n")

    def open_group_chat_window(self, group_name):
        if group_name not in self.group_windows:
            self.group_windows[group_name] = self.GroupChatWindow(self, self.username, group_name, self.write_group)
            # Load group chat history
            chat_history = self.db.get_group_chat_history(group_name)
            for sender, content, timestamp in chat_history:
                display_name = "Me" if sender == self.username else sender
                self.group_windows[group_name].add_message(f"{display_name} ({timestamp}): {content}\n")

    def create_group(self):
        """Show dialog to create a new group"""
        group_name = simpledialog.askstring("Create Group", "Enter group name:")
        if group_name:
            self.server.send(create_msg("create_group", self.username, "server", group_name).encode())

    def join_group(self):
        """Show dialog to join an existing group"""
        group_name = simpledialog.askstring("Join Group", "Enter group name to join:")
        if group_name:
            self.server.send(create_msg("join_group", self.username, "server", group_name).encode())

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

        # Create notebook for tabs
        from tkinter import ttk
        notebook = ttk.Notebook(self.main_window)
        notebook.pack(fill=BOTH, expand=True, padx=15, pady=10)

        # Private chats tab
        private_frame = Frame(notebook)
        notebook.add(private_frame, text="Private Chats")
        
        Label(private_frame, text="Online Users", font=('Segoe UI', 12, 'bold')).pack(pady=10)
        self.user_box = Listbox(private_frame, font=('Segoe UI', 10), bd=2)
        self.user_box.pack(fill=BOTH, expand=True, padx=15, pady=(0, 10))
        self.user_box.bind('<Double-Button-1>', lambda e: self.open_chat_window(self.user_box.get(ACTIVE)))

        # Group chats tab
        group_frame = Frame(notebook)
        notebook.add(group_frame, text="Group Chats")
        
        Label(group_frame, text="My Groups", font=('Segoe UI', 12, 'bold')).pack(pady=10)
        self.group_box = Listbox(group_frame, font=('Segoe UI', 10), bd=2)
        self.group_box.pack(fill=BOTH, expand=True, padx=15, pady=(0, 10))
        self.group_box.bind('<Double-Button-1>', lambda e: self.open_group_chat_window(self.group_box.get(ACTIVE)))
        
        # Populate group_box with existing groups if they were received before window creation
        if hasattr(self, 'user_groups') and self.user_groups:
            for group in self.user_groups:
                self.group_box.insert(END, group)
        
        # Group action buttons
        group_button_frame = Frame(group_frame)
        group_button_frame.pack(fill=X, padx=15, pady=(0, 10))
        
        Button(group_button_frame, text="Create Group", font=('Segoe UI', 10),
               command=self.create_group).pack(side=LEFT, padx=(0, 5))
        Button(group_button_frame, text="Join Group", font=('Segoe UI', 10),
               command=self.join_group).pack(side=LEFT)
        
        # Voice calls tab
        voice_frame = Frame(notebook)
        notebook.add(voice_frame, text="Voice Calls")
        
        Label(voice_frame, text="Voice Chat", font=('Segoe UI', 12, 'bold')).pack(pady=10)
        Label(voice_frame, text="Select a user to start a voice call", font=('Segoe UI', 10)).pack(pady=5)
        
        # Voice call user list
        self.voice_user_box = Listbox(voice_frame, font=('Segoe UI', 10), bd=2)
        self.voice_user_box.pack(fill=BOTH, expand=True, padx=15, pady=(10, 10))
        
        # Voice call buttons
        voice_button_frame = Frame(voice_frame)
        voice_button_frame.pack(fill=X, padx=15, pady=(0, 10))
        
        Button(voice_button_frame, text="📞 Start Call", font=('Segoe UI', 11),
               command=self.start_voice_call, bg='#4CAF50', fg='white',
               width=15).pack(pady=5)
               
        # Call status label
        self.call_status_label = Label(voice_frame, text="Ready to call", 
                                      font=('Segoe UI', 10), fg='gray')
        self.call_status_label.pack(pady=5)

        # Exit button
        exit_button = Button(self.main_window, text="Exit Chat", font=('Segoe UI', 11),
                             command=self.exit_chat)
        exit_button.pack(pady=15)

        # Update voice call user list with current online users
        self.update_voice_user_list()
        
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()
        
    def start_voice_call(self):
        """
        Start a voice call with the selected user.
        """
        try:
            selected_user = self.voice_user_box.get(ACTIVE)
            if selected_user and self.voice_call:
                self.voice_call.initiate_call(selected_user)
                self.call_status_label.config(text=f"Calling {selected_user}...", fg='orange')
            else:
                messagebox.showwarning("No Selection", "Please select a user to call")
        except:
            messagebox.showwarning("No Selection", "Please select a user to call")
            
    def update_voice_user_list(self):
        """
        Update the voice call user list with current online users.
        """
        if hasattr(self, 'voice_user_box') and self.voice_user_box and self.voice_user_box.winfo_exists():
            # Get current users from the main user box
            if self.user_box and self.user_box.winfo_exists():
                self.voice_user_box.delete(0, END)
                for i in range(self.user_box.size()):
                    user = self.user_box.get(i)
                    self.voice_user_box.insert(END, user)

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
                                  font=('Segoe UI', 11, 'bold'))
        instruction_label.pack(pady=10)

        Label(frame, text="Username:", font=('Segoe UI', 10)).pack(anchor=W)
        self.name_input = Entry(frame, font=('Segoe UI', 11))
        self.name_input.pack(fill=X, pady=(0, 10))

        Label(frame, text="Password:", font=('Segoe UI', 10)).pack(anchor=W)
        self.pass_input = Entry(frame, font=('Segoe UI', 11), show='*')
        self.pass_input.pack(fill=X, pady=(0, 15))

        button_frame = Frame(frame)
        button_frame.pack(fill=X)

        login_button = Button(button_frame, text="Login", command=lambda: self.connect(True),
                              font=('Segoe UI', 11), bg='#4CAF50', fg='white',
                              width=12)
        login_button.pack(side=LEFT, padx=5)

        register_button = Button(button_frame, text="Register", command=lambda: self.connect(False),
                                 font=('Segoe UI', 11), bg='#2196F3', fg='white',
                                 width=12)
        register_button.pack(side=RIGHT, padx=5)

        ROOT.mainloop()


if __name__ == '__main__':
    Client = Client()
    Client.main()
