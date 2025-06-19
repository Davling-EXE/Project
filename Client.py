
from tkinter import *
import socket
from Protocol import *
from tkinter import messagebox, simpledialog
import threading
from tkinter.scrolledtext import ScrolledText
from Encryption import RSAEncryption, AESEncryption
from Call import VoiceCall # Import VoiceCall class
import sys

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
ROOT.title("Zephyr Chat Login")


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
        self.group_box = None
        self.voice_chat_box = None
        self.end_call_button = None
        self.voice_chat_tab = None
        self.server = None          # Socket connection to server
        self.user_box = None       # Listbox for displaying online users
        self.top = None            # Reference to top-level window
        self.name_input = None     # Username input field
        self.pass_input = None     # Password input field
        self.username = ""         # Current user's username
        self.chat_windows = {}     # Active chat windows {username: ChatWindow}
        self.group_windows = {}    # Active group chat windows {group_name: ChatWindow}
        self.main_window = None    # Main application window
        self.rsa = RSAEncryption()
        self.aes = None # AES for TCP messages with server
        self.peer_public_keys = {}
        self.user_groups = []      # List of groups user belongs to
        self.current_voice_call = None # Holds the active VoiceCall object
        self.call_aes_key = None # AES key specifically for the current voice call

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

            self.server = socket.socket()
            self.server.connect((SERVER_IP, PORT))

            # Send login or register request to server
            auth_type = "login" if is_login else "register"
            # Content format: password-public_key
            auth_content = f"{password}-{self.rsa.export_public_key().decode()}"
            auth_msg = create_msg(auth_type, username, "server", auth_content)
            self.server.send(auth_msg.encode())

            # Wait for authentication response
            auth_response_type, _, _, auth_response_content = parse_msg(self.server)

            if auth_response_type not in ["login_success", "register_success"]:
                messagebox.showerror("Authentication Error", auth_response_content)
                self.server.close()
                self.server = None
                return
            
            # Proceed with connection if auth is successful
            self.username = username
            # The server's response to successful auth (auth_response_content) contains its public key.
            # We use this to encrypt and send our AES key.
            
            server_pub_key_str = auth_response_content
            server_pub_key = server_pub_key_str.encode()

            # Generate AES key and send it encrypted to server
            self.aes = AESEncryption() # Creates a new random AES key
            encrypted_aes_key = self.rsa.encrypt_with_public_key(self.aes.key, server_pub_key)
            aes_msg = create_msg("aes_key", self.username, "server", encrypted_aes_key.hex())
            print(f"Sending AES key message: {aes_msg}")
            self.server.send(aes_msg.encode())

            # At this point, the server will process the AES key and then start sending user lists, group lists, etc.
            # The main receive loop will handle these subsequent messages.

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
                if msg_type == "chat_history":
                    if self.aes:
                        try:
                            history_data = self.aes.decrypt(bytes.fromhex(content)).decode()
                            for history_item in history_data.split('\n'):
                                if history_item:
                                    sender_name, msg_content, timestamp = history_item.split('|')
                                    display_name = "Me" if sender_name == self.username else sender_name
                                    if recipient in self.chat_windows:
                                        self.chat_windows[recipient].add_message(f"{display_name} ({timestamp}): {msg_content}\n")
                        except Exception:
                            print("Failed to process chat history")

                elif msg_type == "group_chat_history":
                    if self.aes:
                        try:
                            history_data = self.aes.decrypt(bytes.fromhex(content)).decode()
                            for history_item in history_data.split('\n'):
                                if history_item:
                                    sender_name, msg_content, timestamp = history_item.split('|')
                                    display_name = "Me" if sender_name == self.username else sender_name
                                    if recipient in self.group_windows:
                                        self.group_windows[recipient].add_message(f"{display_name} ({timestamp}): {msg_content}\n")
                        except Exception:
                            print("Failed to process group chat history")

                elif msg_type == "message":
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
                # Voice Call Message Handling
                elif msg_type == "call_request": # Incoming call request from another user
                    call_initiator = sender
                    # Content is the AES key for the call, proposed by the initiator
                    proposed_call_aes_key_hex = content
                    if self.current_voice_call:
                        # Already in a call, send busy or ignore
                        self.server.send(create_msg("call_reject", self.username, call_initiator, "busy").encode()) # Inform initiator you're busy
                        # if call_initiator not in self.chat_windows: self.open_chat_window(call_initiator)
                        # self.chat_windows[call_initiator].add_message(f"Incoming call from {call_initiator} while you're busy.\n")
                        print(f"Incoming call from {call_initiator} while busy.") # Log to console instead
                    elif messagebox.askyesno("Incoming Call", f"{call_initiator} is calling you. Accept?"):
                        self.call_aes_key = bytes.fromhex(proposed_call_aes_key_hex)
                        self.current_voice_call = VoiceCall(self.server, self.username, call_initiator, SERVER_IP, PORT, False, self.call_aes_key)
                        self.server.send(create_msg("call_accept", self.username, call_initiator, "").encode()) # Accept, AES key is implicit
                        self.server.send(create_msg("udp_info", self.username, "server", str(self.current_voice_call.udp_port)).encode()) # Send my UDP info for relay
                        # if call_initiator not in self.chat_windows: self.open_chat_window(call_initiator)
                        # self.chat_windows[call_initiator].add_message(f"Call accepted with {call_initiator}. Waiting for server relay setup...\n")
                        print(f"Call accepted with {call_initiator}. Waiting for server relay setup...") # Log to console instead
                    else:
                        self.server.send(create_msg("call_reject", self.username, call_initiator, "rejected").encode())
                        # if call_initiator not in self.chat_windows: self.open_chat_window(call_initiator)
                        # self.chat_windows[call_initiator].add_message(f"Call from {call_initiator} rejected.\n")
                        print(f"Call from {call_initiator} rejected.") # Log to console instead
                elif msg_type == "call_accept": # Your previously initiated call was accepted
                    accepted_by = sender
                    if self.current_voice_call and self.current_voice_call.recipient_username == accepted_by:
                        self.server.send(create_msg("udp_info", self.username, "server", str(self.current_voice_call.udp_port)).encode()) # Send my UDP info for relay
                        # if accepted_by not in self.chat_windows: self.open_chat_window(accepted_by)
                        # self.chat_windows[accepted_by].add_message(f"{accepted_by} accepted your call. Waiting for server relay setup...\n")
                        print(f"{accepted_by} accepted your call. Waiting for server relay setup...") # Log to console instead
                    else:
                        # This case should ideally not happen if state is managed well
                        print(f"Received call_accept from {accepted_by}, but no matching pending call found or wrong recipient.")
                elif msg_type == "call_reject":
                    rejected_by = sender
                    reason = content # "busy" or "rejected"
                    if self.current_voice_call and self.current_voice_call.recipient_username == rejected_by:
                        # if rejected_by not in self.chat_windows: self.open_chat_window(rejected_by)
                        # self.chat_windows[rejected_by].add_message(f"Call to {rejected_by} was not established: {reason}.\n")
                        print(f"Call to {rejected_by} was not established: {reason}.") # Log to console instead
                        self.end_current_call_ui(notify_server=False) # Server already handled or peer rejected
                    else: # Call was rejected by someone else or no active call UI
                        # if rejected_by not in self.chat_windows: self.open_chat_window(rejected_by)
                        # self.chat_windows[rejected_by].add_message(f"{rejected_by} could not be reached or rejected the call: {reason}.\n")
                        print(f"{rejected_by} could not be reached or rejected the call: {reason}.") # Log to console instead
                elif msg_type == "call_busy": # Server informs that the callee is busy
                    busy_user = content.split(' ')[0] # Assuming content is like "UserX is already in a call."
                    if self.current_voice_call and self.current_voice_call.recipient_username == busy_user:
                        # if busy_user not in self.chat_windows: self.open_chat_window(busy_user)
                        # self.chat_windows[busy_user].add_message(f"Could not call {busy_user}. User is busy.\n")
                        print(f"Could not call {busy_user}. User is busy.") # Log to console instead
                        self.end_current_call_ui(notify_server=False)
                elif msg_type == "call_ready_relay": # Server confirms both UDPs received, ready for relay
                    # Content might be empty or contain confirmation details, not strictly needed for now
                    if self.current_voice_call:
                        self.current_voice_call.start_call() # Start sending/receiving audio (now to/from server)
                        peer_user = self.current_voice_call.recipient_username
                        print(f"Voice call with {peer_user} connected via server relay!")
                        if hasattr(self, 'voice_chat_box') and self.voice_chat_box.winfo_exists():
                            for i in range(self.voice_chat_box.size()):
                                if peer_user in self.voice_chat_box.get(i):
                                    self.voice_chat_box.delete(i)
                                    self.voice_chat_box.insert(i, f"{peer_user} (In Call - Relay)")
                                    break
                            else: # If not found
                                self.voice_chat_box.insert(END, f"{peer_user} (In Call - Relay)")
                            if hasattr(self, 'end_call_button'): self.end_call_button.config(state="normal")
                    else:
                        print("Received call_ready_relay but no active call found.")
                elif msg_type == "call_end":
                    ended_by = sender
                    reason = content # e.g., "Disconnected" or empty
                    if self.current_voice_call and (self.current_voice_call.recipient_username == ended_by or self.current_voice_call.username == ended_by):
                        peer_user = self.current_voice_call.recipient_username if self.current_voice_call.username == ended_by else self.current_voice_call.username
                        # if peer_user not in self.chat_windows: self.open_chat_window(peer_user)
                        # self.chat_windows[peer_user].add_message(f"Call with {ended_by} ended. Reason: {reason if reason else 'Normal termination'}\n")
                        print(f"Call with {ended_by} ended. Reason: {reason if reason else 'Normal termination'}") # Log to console instead
                        self.end_current_call_ui(notify_server=False) # Server already knows or initiated
                        if hasattr(self, 'voice_chat_box') and self.voice_chat_box.winfo_exists():
                            for i in range(self.voice_chat_box.size()):
                                if peer_user in self.voice_chat_box.get(i):
                                    self.voice_chat_box.delete(i)
                                    break


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

            # Close main window if it exists
            if self.main_window and self.main_window.winfo_exists():
                self.main_window.destroy()

            # Close root window and exit program
            if self.current_voice_call: # Ensure voice call is ended before exiting
                self.end_current_call_ui(notify_server=True)
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
            self.end_call_button = None
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
            top_frame.pack(fill="x", padx=15, pady=10)

            exit_button = Button(top_frame, text="Close Chat", font=('Segoe UI', 10),
                                 command=self.exit_chat)
            exit_button.pack(side="right")

            # Chat display area
            self.chat_box = ScrolledText(self.window, font=('Segoe UI', 10), bd=2)
            self.chat_box.pack(fill="both", expand=True, padx=15, pady=10)

            # Input area
            bottom_frame = Frame(self.window)
            bottom_frame.pack(fill="x", padx=15, pady=(0, 15))

            self.send_input = Entry(bottom_frame, font=('Segoe UI', 10), bd=2)
            self.send_input.pack(side="left", expand=True, fill="x", padx=(0, 10))
            self.send_input.bind('<Return>', self.send_message)

            send_button = Button(bottom_frame, text="Send", font=('Segoe UI', 10),
                                 command=self.send_message)
            send_button.pack(side="right")

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

        def add_end_call_button(self, client_ref, peer_username):
            if not hasattr(self, 'end_call_button') or not self.end_call_button or not self.end_call_button.winfo_exists():
                self.end_call_button = Button(self.window, text="End Call", command=lambda: client_ref.end_current_call_ui(notify_server=True, peer=peer_username))
                self.end_call_button.pack(side="bottom", pady=5)

        def remove_end_call_button(self):
            if hasattr(self, 'end_call_button') and self.end_call_button and self.end_call_button.winfo_exists():
                self.end_call_button.destroy()
                self.end_call_button = None

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
            top_frame.pack(fill="x", padx=15, pady=10)

            exit_button = Button(top_frame, text="Close Chat", font=('Segoe UI', 10),
                                 command=self.exit_chat)
            exit_button.pack(side="right")

            # Chat display area
            self.chat_box = ScrolledText(self.window, font=('Segoe UI', 10), bd=2)
            self.chat_box.pack(fill="both", expand=True, padx=15, pady=10)

            # Input area
            bottom_frame = Frame(self.window)
            bottom_frame.pack(fill="x", padx=15, pady=(0, 15))

            self.send_input = Entry(bottom_frame, font=('Segoe UI', 10), bd=2)
            self.send_input.pack(side="left", expand=True, fill="x", padx=(0, 10))
            self.send_input.bind('<Return>', self.send_message)

            send_button = Button(bottom_frame, text="Send", font=('Segoe UI', 10),
                                 command=self.send_message)
            send_button.pack(side="right")

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
            # Request chat history from server
            if self.aes:
                self.server.send(create_msg("get_chat_history", self.username, recipient, "").encode())

    def open_group_chat_window(self, group_name):
        if group_name not in self.group_windows:
            self.group_windows[group_name] = self.GroupChatWindow(self, self.username, group_name, self.write_group)
            # Request group chat history from server
            if self.aes:
                self.server.send(create_msg("get_group_chat_history", self.username, group_name, "").encode())

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
        self.main_window.title(f"Zephyr Contacts - {self.username}")
        self.main_window.geometry(self.get_window_position(350, 500))
        self.main_window.minsize(300, 400)

        # Configure window close protocol
        self.main_window.protocol("WM_DELETE_WINDOW", self.exit_chat)

        # Create notebook for tabs
        from tkinter import ttk
        notebook = ttk.Notebook(self.main_window)
        notebook.pack(fill="both", expand=True, padx=15, pady=10)

        # Private chats tab
        private_frame = Frame(notebook)
        notebook.add(private_frame, text="Private Chats")

        Label(private_frame, text="Online Users", font=('Segoe UI', 12, 'bold')).pack(pady=10)
        self.user_box = Listbox(private_frame, font=('Segoe UI', 10), bd=2)
        self.user_box.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        self.user_box.bind('<Double-Button-1>', self.open_chat_from_list) # Changed binding

        # Group chats tab
        group_frame = Frame(notebook)
        notebook.add(group_frame, text="Group Chats")

        self.voice_chat_tab = Frame(notebook) # Corrected from self.notebook to notebook
        notebook.add(self.voice_chat_tab, text='Voice Chat') # Corrected from self.notebook to notebook
        Label(self.voice_chat_tab, text="Active Voice Chats:").pack(pady=5)
        self.voice_chat_box = Listbox(self.voice_chat_tab, height=10, width=50)
        self.voice_chat_box.pack(pady=5, padx=10, fill="both", expand=True)
        
        button_frame = Frame(self.voice_chat_tab)
        button_frame.pack(pady=5)

        start_call_button = Button(button_frame, text="Start New Call", command=self.prompt_initiate_call_from_tab)
        start_call_button.pack(side="left", padx=5)

        self.end_call_button = Button(button_frame, text="End Current Call", command=self.handle_end_call_button, state="disabled")
        self.end_call_button.pack(side="left", padx=5)

        # Add binding for voice_chat_box later if needed
        # self.voice_chat_box.bind('<Double-Button-1>', self.some_voice_chat_action)

        Label(group_frame, text="My Groups", font=('Segoe UI', 12, 'bold')).pack(pady=10)
        self.group_box = Listbox(group_frame, font=('Segoe UI', 10), bd=2)
        self.group_box.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        self.group_box.bind('<Double-Button-1>', lambda e: self.open_group_chat_window(self.group_box.get(ACTIVE)))

        # Populate group_box with existing groups if they were received before window creation
        if hasattr(self, 'user_groups') and self.user_groups:
            for group in self.user_groups:
                self.group_box.insert(END, group)

        # Group action buttons
        group_button_frame = Frame(group_frame)
        group_button_frame.pack(fill="x", padx=15, pady=(0, 10))

        Button(group_button_frame, text="Create Group", font=('Segoe UI', 10),
               command=self.create_group).pack(side="left", padx=(0, 5))
        Button(group_button_frame, text="Join Group", font=('Segoe UI', 10),
               command=self.join_group).pack(side="left")

        # Exit button
        exit_button = Button(self.main_window, text="Exit Chat", font=('Segoe UI', 11),
                             command=self.exit_chat)
        exit_button.pack(pady=15)

        receive_thread = threading.Thread(target=self.receive, daemon=True)
        receive_thread.start()

    def initiate_call_prompt_from_list(self):
        selected_index = self.user_box.curselection()
        if not selected_index:
            messagebox.showwarning("Selection Error", "Please select a user to call.")
            return
        recipient_username = self.user_box.get(selected_index[0])
        self.initiate_call_to_user(recipient_username)

    def handle_end_call_button(self):
        if self.current_voice_call:
            # No need to ask for confirmation, just end the current call
            self.end_current_call_ui(notify_server=True)
        else:
            messagebox.showinfo("Info", "No active call to end.")
            if hasattr(self, 'end_call_button'): self.end_call_button.config(state="disabled")

    def initiate_call_to_user(self, recipient_username):
        if recipient_username == self.username:
            messagebox.showerror("Call Error", "You cannot call yourself.")
            return

        if self.current_voice_call:
            messagebox.showerror("Call Error", f"You are already in a call with {self.current_voice_call.recipient_username}. Please end it first.")
            return

        if messagebox.askyesno("Initiate Call", f"Do you want to call {recipient_username}?"):
            self.call_aes_key = AESEncryption().key # Generate a new AES key for this call
            self.current_voice_call = VoiceCall(self.server, self.username, recipient_username, SERVER_IP, PORT, True, self.call_aes_key)
            # Send call request with the new AES key for the call
            self.server.send(create_msg("call_request", self.username, recipient_username, self.call_aes_key.hex()).encode())
            # if recipient_username not in self.chat_windows:
            #     self.open_chat_window(recipient_username)
            # self.chat_windows[recipient_username].add_message(f"Calling {recipient_username}... Waiting for response.\n")
            print(f"Calling {recipient_username}... Waiting for response.") # Log to console instead
            if hasattr(self, 'voice_chat_box') and self.voice_chat_box.winfo_exists():
                # Remove if already exists (e.g. previous call attempt)
                for i in range(self.voice_chat_box.size()):
                    if recipient_username in self.voice_chat_box.get(i):
                        self.voice_chat_box.delete(i)
                        break
                self.voice_chat_box.insert(END, f"{recipient_username} (Calling...)")

    def prompt_initiate_call_from_tab(self):
        recipient_username = simpledialog.askstring("Start Voice Call", "Enter username to call:", parent=self.main_window)
        if recipient_username:
            self.initiate_call_to_user(recipient_username)

    def open_chat_from_list(self, event=None):
        if not self.user_box:
            return
        selected_indices = self.user_box.curselection()
        if not selected_indices:
            return
        recipient_username = self.user_box.get(selected_indices[0])
        if recipient_username == self.username:
            # Optionally, show an error or just do nothing
            return
        self.open_chat_window(recipient_username)

    def end_current_call_ui(self, notify_server=True):
        if self.current_voice_call:
            recipient_username = self.current_voice_call.recipient_username
            print(f"Ending call UI for {recipient_username}. Current voice call object: {self.current_voice_call}")
            if notify_server:
                # Only send call_end if the call was actually established or in a state where server needs notification
                # For calls that never connected (e.g. user not found), server might handle it differently
                # or this client action might be redundant if server already sent an error/reject.
                # Consider if server needs a specific message for 'call attempt failed client side'.
                self.server.send(create_msg("call_end", self.username, recipient_username, "Disconnected by user").encode())
            
            self.current_voice_call.end_call() # stop streams and threads
            
            # Remove from voice_chat_box
            if hasattr(self, 'voice_chat_box') and self.voice_chat_box.winfo_exists():
                try:
                    items = list(self.voice_chat_box.get(0, END))
                    for i, item_text in enumerate(items):
                        # Match recipient_username, potentially with status like (Calling...) or (In Call)
                        if recipient_username in item_text.split(' ')[0]: 
                            self.voice_chat_box.delete(i)
                            break
                except TclError: # Widget might be destroyed
                    pass

            self.current_voice_call = None # Crucial: Clear the current call object
            self.call_aes_key = None # Clear AES key for the ended call
            if hasattr(self, 'end_call_button'): self.end_call_button.config(state="disabled")
            
            # Re-enable call initiation buttons if they were disabled
            # (This part might need more specific logic depending on UI setup)
            print(f"Call UI ended and current_voice_call reset for {recipient_username}.")
        else:
            print("end_current_call_ui called but no current_voice_call object exists.")

    def main(self):
        """Initialize and run the main application.

        Creates the login/register window with input fields and buttons.
        Sets up the main event loop for the application.
        """
        # Create login/register window
        ROOT.geometry(self.get_window_position(300, 250))
        ROOT.minsize(250, 250)
        frame = Frame(ROOT, padx=20, pady=20)
        frame.pack(expand=True, fill="both")

        instruction_label = Label(frame, text="Welcome to Chat",
                                  font=('Segoe UI', 11, 'bold'))
        instruction_label.pack(pady=10)

        Label(frame, text="Username:", font=('Segoe UI', 10)).pack(anchor="w")
        self.name_input = Entry(frame, font=('Segoe UI', 11))
        self.name_input.pack(fill="x", pady=(0, 10))

        Label(frame, text="Password:", font=('Segoe UI', 10)).pack(anchor="w")
        self.pass_input = Entry(frame, font=('Segoe UI', 11), show='*')
        self.pass_input.pack(fill="x", pady=(0, 15))

        button_frame = Frame(frame)
        button_frame.pack(fill="x")

        login_button = Button(button_frame, text="Login", command=lambda: self.connect(True),
                              font=('Segoe UI', 11), bg='#4CAF50', fg='white',
                              width=12)
        login_button.pack(side="left", padx=5)

        register_button = Button(button_frame, text="Register", command=lambda: self.connect(False),
                                 font=('Segoe UI', 11), bg='#2196F3', fg='white',
                                 width=12)
        register_button.pack(side="right", padx=5)

        ROOT.mainloop()


if __name__ == '__main__':
    Client = Client()
    Client.main()
