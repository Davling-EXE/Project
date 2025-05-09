
from tkinter import *
import socket
from Protocol import *
from tkinter import messagebox
import threading
from tkinter.scrolledtext import ScrolledText
from database import Database
from Encryption import RSAEncryption, AESEncryption
import pyaudio # Added for voice call
import time # Added for voice call (potentially)
from typing import Optional, Dict, Any, Callable

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
        self.server: Optional[socket.socket] = None          # Socket connection to server
        self.user_box: Optional[Listbox] = None       # Listbox for displaying online users
        self.top: Optional[Toplevel] = None            # Reference to top-level window
        self.name_input: Optional[Entry] = None     # Username input field
        self.pass_input: Optional[Entry] = None     # Password input field
        self.username: str = ""         # Current user's username
        self.chat_windows: Dict[str, Client.ChatWindow] = {}     # Active chat windows {username: ChatWindow}
        self.main_window: Optional[Toplevel] = None    # Main application window
        self.db: Database = Database()       # Database connection
        self.rsa: RSAEncryption = RSAEncryption()
        self.aes: Optional[AESEncryption] = None
        self.peer_public_keys: Dict[str, bytes] = {}
        self.p_audio: Optional[pyaudio.PyAudio] = None  # PyAudio instance for voice calls
        self.active_calls: Dict[str, Dict[str, Any]] = {}  # To store active call data {recipient: CallData}
        self.voice_call_windows: Dict[str, Client.VoiceCallWindow] = {} # To store voice call window instances {recipient: VoiceCallWindow}

    def get_window_position(self, width: int, height: int) -> str:
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

    def connect(self, is_login: bool = True) -> None:
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
            # Exchange public keys
            self.server.send(create_msg("connect", self.username, "server", self.rsa.export_public_key().decode()).encode())
            msg_type, sender, recipient, content = parse_msg(self.server)
            if msg_type == "connect":
                # Receive server's public key and AES key encrypted for us
                server_pub_key = content.encode()
                # Generate AES key and send it encrypted to server
                self.aes = AESEncryption()
                encrypted_aes = self.rsa.encrypt_with_public_key(self.aes.key, server_pub_key)
                self.server.send(create_msg("aes_key", self.username, "server", encrypted_aes.hex()).encode())
            elif msg_type == "error":
                messagebox.showerror("Connection Error", content)
                self.server.close()
                return
            messagebox.showinfo("Connected successfully", f"Connected as {self.username}")
            self.open_chat()

        except socket.error as err:
            messagebox.showerror("Connection Error", str(err))

    def _handle_message(self, sender: str, content: str) -> None:
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

    def _handle_error(self, content: str) -> bool:
        messagebox.showerror("Error", content)
        if hasattr(self, 'top') and self.top:
            self.top.destroy()
        return True # Indicates loop should break

    def _handle_user_list(self, content: str) -> None:
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

    def _handle_server_connect(self, content: str) -> None:
        messagebox.showinfo("Server Message", content)

    def _handle_call_request(self, caller_username: str, content: str) -> None:
        # content should be "caller_username,caller_udp_port" - but caller_username is already sender
        # Actually, content is just caller_udp_port_str
        caller_udp_port_str = content
        caller_udp_port = int(caller_udp_port_str)
        if messagebox.askyesno("Incoming Call", f"{caller_username} is calling you. Accept?"):
            my_udp_port = self.find_available_udp_port()
            if not my_udp_port:
                messagebox.showerror("Call Error", "No available UDP port to accept the call.")
                self.server.send(create_msg("call_reject", self.username, caller_username, "No available port").encode())
                return
            self.active_calls[caller_username] = {'status': 'accepting', 'my_udp_port': my_udp_port, 'peer_udp_port': caller_udp_port, 'stop_event': threading.Event(), 'audio_started': False}
            self.server.send(create_msg("call_accept", self.username, caller_username, str(my_udp_port)).encode())
            self.open_voice_call_window(caller_username, peer_ip=SERVER_IP, peer_udp_port=caller_udp_port, my_udp_port=my_udp_port, is_caller=False)
        else:
            self.server.send(create_msg("call_reject", self.username, caller_username, "Call rejected by user").encode())

    def _handle_call_accept(self, acceptor_username: str, content: str) -> None:
        # content should be "acceptor_username,acceptor_udp_port" - acceptor_username is already sender
        # Actually, content is just acceptor_udp_port_str
        try:
            acceptor_udp_port = int(content)
            if acceptor_username in self.active_calls and self.active_calls[acceptor_username]['status'] == 'calling':
                self.active_calls[acceptor_username]['status'] = 'active'
                self.active_calls[acceptor_username]['peer_udp_port'] = acceptor_udp_port
                my_udp_port = self.active_calls[acceptor_username]['my_udp_port']

                # Ensure voice call window is opened before trying to start streams
                if acceptor_username not in self.voice_call_windows:
                    self.open_voice_call_window(acceptor_username, peer_ip=SERVER_IP, peer_udp_port=acceptor_udp_port, my_udp_port=my_udp_port, is_caller=True)
                
                if acceptor_username in self.voice_call_windows and not self.active_calls[acceptor_username].get('audio_started', False):
                    self.voice_call_windows[acceptor_username].start_audio_streams()
                    self.active_calls[acceptor_username]['audio_started'] = True
                else:
                    print(f"Audio streams already started or window not found for {acceptor_username}")

            else:
                print(f"Received call_accept from {acceptor_username} but no pending call found or wrong state.")
        except ValueError:
            print(f"Invalid UDP port received from {acceptor_username}: {content}")
        except Exception as e:
            print(f"Error handling call_accept from {acceptor_username}: {e}")

    def _handle_call_reject(self, rejector_username: str, content: str) -> None:
        # content is "reason"
        reason = content
        messagebox.showinfo("Call Rejected", f"{rejector_username} rejected the call: {reason}")
        if rejector_username in self.active_calls:
            if 'stop_event' in self.active_calls[rejector_username]:
                self.active_calls[rejector_username]['stop_event'].set()
            del self.active_calls[rejector_username]
        if rejector_username in self.voice_call_windows:
            try:
                self.voice_call_windows[rejector_username].window.destroy()
            except tk.TclError:
                pass # Window might already be destroyed
            del self.voice_call_windows[rejector_username]

    def _handle_call_hangup(self, hangupper_username: str, content: str) -> None:
        # content is empty for call_hangup
        messagebox.showinfo("Call Ended", f"{hangupper_username} ended the call.")
        if hangupper_username in self.active_calls:
            self.active_calls[hangupper_username]['stop_event'].set()
            call_data = self.active_calls[hangupper_username]
            if call_data.get('audio_started', False) and hangupper_username in self.voice_call_windows:
                 vc_window = self.voice_call_windows[hangupper_username]
                 if hasattr(vc_window, 'sender_thread') and vc_window.sender_thread.is_alive():
                     vc_window.sender_thread.join(timeout=1)
                 if hasattr(vc_window, 'receiver_thread') and vc_window.receiver_thread.is_alive():
                     vc_window.receiver_thread.join(timeout=1)
            del self.active_calls[hangupper_username]
        if hangupper_username in self.voice_call_windows:
            self.voice_call_windows[hangupper_username].window.destroy()
            del self.voice_call_windows[hangupper_username]

    def _handle_call_error(self, other_user: str, content: str) -> None:
        # content is "error_message"
        error_message = content
        messagebox.showerror("Call Error", f"Call error with {other_user}: {error_message}")
        if other_user in self.active_calls:
            if 'stop_event' in self.active_calls[other_user]:
                self.active_calls[other_user]['stop_event'].set()
            del self.active_calls[other_user]
        if other_user in self.voice_call_windows:
            self.voice_call_windows[other_user].window.destroy()
            del self.voice_call_windows[other_user]

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
                    self._handle_message(sender, content)
                elif msg_type == "error":
                    if self._handle_error(content):
                        break
                elif msg_type == "user_list":
                    self._handle_user_list(content)
                # Removed duplicate "message" handler here
                elif msg_type == "connect" and sender == "server":
                    self._handle_server_connect(content)
                elif msg_type == "call_request": 
                    # Original content: "caller_username,caller_udp_port"
                    # parse_msg gives sender as caller_username, so content is just caller_udp_port_str
                    self._handle_call_request(sender, content.split(',', 1)[1] if ',' in content else content) 
                elif msg_type == "call_accept": 
                    # Original content: "acceptor_username,acceptor_udp_port"
                    # parse_msg gives sender as acceptor_username, so content is just acceptor_udp_port_str
                    self._handle_call_accept(sender, content.split(',', 1)[1] if ',' in content else content)
                elif msg_type == "call_reject":
                    # Original content: "rejector_username,reason"
                    # parse_msg gives sender as rejector_username, so content is just reason
                    self._handle_call_reject(sender, content.split(',', 1)[1] if ',' in content else content)
                elif msg_type == "call_hangup":
                    # Original content: "hangupper_username"
                    # parse_msg gives sender as hangupper_username, content is empty
                    self._handle_call_hangup(sender, content) 
                elif msg_type == "call_error": 
                    # Original content: "other_user,error_message"
                    # parse_msg gives sender as other_user, so content is just error_message
                    self._handle_call_error(sender, content.split(',', 1)[1] if ',' in content else content)

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
            
            # Close main window if it exists
            if self.main_window and self.main_window.winfo_exists():
                self.main_window.destroy()
            
            # Stop any active calls
            active_call_recipients = list(self.active_calls.keys())
            for recipient in active_call_recipients:
                if recipient in self.voice_call_windows and self.voice_call_windows[recipient].window.winfo_exists():
                    self.voice_call_windows[recipient].hang_up_call() # This should also clean up active_calls entry
                elif recipient in self.active_calls: # If window was closed but call data persists
                    self.active_calls[recipient]['stop_event'].set()
                    # Send hangup if not already handled by window closure
                    self.server.send(create_msg("call_hangup", self.username, recipient, "").encode())
                    del self.active_calls[recipient]

            # Terminate PyAudio
            if self.p_audio:
                print("Terminating PyAudio...")
                self.p_audio.terminate()
                self.p_audio = None
                print("PyAudio terminated.")

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
            send_button.pack(side=LEFT, padx=(0,5))

            call_button = Button(bottom_frame, text="Call", font=('Segoe UI', '10'),
                                 command=lambda: self.parent.initiate_voice_call(self.recipient))
            call_button.pack(side=RIGHT)

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

    def initiate_voice_call(self, recipient):
        if recipient == self.username:
            messagebox.showerror("Call Error", "You cannot call yourself.")
            return
        if recipient in self.active_calls:
            messagebox.showinfo("Call Info", f"You are already in a call or initiating a call with {recipient}.")
            return
        
        # Placeholder for actual call initiation logic
        # This will involve sending a call request to the server
        print(f"Initiating voice call with {recipient}")
        # For now, let's just open the voice call window directly for UI testing
        # In a real scenario, this window would open after the call is accepted.
        # self.open_voice_call_window(recipient, is_caller=True)
        # Send call request to server
        my_udp_port = self.find_available_udp_port() # We'll need to implement this
        if not my_udp_port:
            messagebox.showerror("Call Error", "No available UDP port for voice call.")
            return
        
        self.server.send(create_msg("call_request", self.username, recipient, str(my_udp_port)).encode())
        # Store call attempt information
        self.active_calls[recipient] = {'status': 'initiating', 'my_udp_port': my_udp_port, 'stop_event': threading.Event()}
        messagebox.showinfo("Call Request Sent", f"Requesting call with {recipient}. Waiting for response...")

    def find_available_udp_port(self):
        """Find an available UDP port for voice calls"""
        # Try ports in a range instead of a fixed port
        for port in range(50000, 50100):
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_socket.bind(('0.0.0.0', port))
                test_socket.close()
                return port
            except OSError:
                continue
        return None  # No available ports found

    def open_voice_call_window(self, recipient, peer_ip=None, peer_udp_port=None, my_udp_port=None, is_caller=False):
        if recipient in self.voice_call_windows and self.voice_call_windows[recipient].window.winfo_exists():
            self.voice_call_windows[recipient].window.lift()
            return
        
        self.voice_call_windows[recipient] = self.VoiceCallWindow(self, self.username, recipient, 
                                                                  peer_ip, peer_udp_port, my_udp_port, is_caller)
        if recipient not in self.active_calls:
             self.active_calls[recipient] = {'status': 'connected', 'stop_event': threading.Event(), 'my_udp_port': my_udp_port, 'peer_udp_port': peer_udp_port}
        else:
            self.active_calls[recipient]['status'] = 'connected'
            self.active_calls[recipient]['peer_udp_port'] = peer_udp_port
            # peer_ip might be useful if not localhost

    class VoiceCallWindow:
        def __init__(self, parent_client: 'Client', username: str, recipient: str, peer_ip: Optional[str], peer_udp_port: Optional[int], my_udp_port: Optional[int], is_caller: bool):
            self.parent_client = parent_client
            self.username = username
            self.recipient = recipient
            self.peer_ip = peer_ip if peer_ip else SERVER_IP
            self.peer_udp_port = peer_udp_port
            self.my_udp_port = my_udp_port
            self.is_caller = is_caller
            
            if recipient not in self.parent_client.active_calls:
                 # This case should ideally not happen if call setup is correct
                 print(f"Error: No active call data for {recipient} when creating VoiceCallWindow.")
                 # Create a dummy stop_event to prevent crashes, but log this issue
                 self.parent_client.active_calls[recipient] = {'stop_event': threading.Event(), 'status': 'error_no_data'}
            self.stop_event = self.parent_client.active_calls[recipient]['stop_event']

            self.window = Toplevel()
            self.window.title(f"Voice Call with {recipient}")
            self.window.geometry(parent_client.get_window_position(300, 200))
            self.window.minsize(250, 150)
            self.window.protocol("WM_DELETE_WINDOW", self.hang_up_call)

            self._setup_ui()

            if self.parent_client.p_audio is None:
                messagebox.showerror("Audio Error", "PyAudio not initialized. Voice call disabled.")
                self.window.destroy()
                # Clean up if window is destroyed during init
                if self.recipient in self.parent_client.voice_call_windows:
                    del self.parent_client.voice_call_windows[self.recipient]
                # Also ensure active_calls is cleaned if this was a new call setup attempt
                if self.recipient in self.parent_client.active_calls and self.parent_client.active_calls[self.recipient].get('status') != 'connected':
                    # If not yet connected, or in an error state, clean up
                    self.parent_client.active_calls[self.recipient]['stop_event'].set()
                    del self.parent_client.active_calls[self.recipient]
                return
            
            self._update_status_based_on_state()

        def _setup_ui(self):
            self.status_label = Label(self.window, text=f"Connecting to {self.recipient}...", font=('Segoe UI', '10'))
            self.status_label.pack(pady=20)

            self.hang_up_button = Button(self.window, text="Hang Up", font=('Segoe UI', '10'), 
                                         command=self.hang_up_call, bg="#f44336", fg="white")
            self.hang_up_button.pack(pady=10)

        def _update_status_based_on_state(self):
            if self.my_udp_port and self.peer_udp_port and self.parent_client.active_calls[self.recipient].get('status') == 'connected':
                # This check is important: only start streams if ports are known AND call is 'connected'
                # The 'connected' status is set in open_voice_call_window or by call_accept handler
                self.status_label.config(text=f"Call with {self.recipient} active.")
                if not self.parent_client.active_calls[self.recipient].get('audio_started', False):
                    self.start_audio_streams()
            elif self.is_caller and self.parent_client.active_calls[self.recipient].get('status') == 'initiating':
                self.status_label.config(text=f"Calling {self.recipient}...")
            elif not self.is_caller and self.parent_client.active_calls[self.recipient].get('status') == 'accepting':
                self.status_label.config(text=f"Incoming call from {self.recipient}...")
            elif self.parent_client.active_calls[self.recipient].get('status') == 'accepted': # For caller, after accept received
                self.status_label.config(text=f"Call with {self.recipient} active.")
                if not self.parent_client.active_calls[self.recipient].get('audio_started', False):
                    self.start_audio_streams()
            else:
                 # Fallback or initial state before ports are fully known
                 current_status = self.parent_client.active_calls[self.recipient].get('status', 'unknown')
                 self.status_label.config(text=f"Call with {self.recipient} ({current_status})")

        def start_audio_streams(self):
            call_data = self.parent_client.active_calls.get(self.recipient)
            if not call_data or call_data.get('audio_started', False):
                print("Audio streams already started or no call data.")
                return

            print(f"Starting audio: Me ({self.my_udp_port}) -> {self.recipient} ({self.peer_ip}:{self.peer_udp_port})")
            self.sender_thread = threading.Thread(target=self.parent_client.send_audio, 
                                                  args=(self.peer_ip, self.peer_udp_port, self.stop_event), daemon=True)
            self.receiver_thread = threading.Thread(target=self.parent_client.receive_audio, 
                                                    args=(self.my_udp_port, self.stop_event), daemon=True)
            self.sender_thread.start()
            self.receiver_thread.start()
            self.parent_client.active_calls[self.recipient]['audio_started'] = True
            self.status_label.config(text=f"Call with {self.recipient} active.")

        def hang_up_call(self):
            print(f"Hanging up call with {self.recipient}")
            call_data = self.parent_client.active_calls.get(self.recipient)

            if call_data:
                call_data['stop_event'].set()
                self.parent_client.server.send(create_msg("call_hangup", self.parent_client.username, self.recipient, "").encode())
                
                if call_data.get('audio_started', False):
                    if hasattr(self, 'sender_thread') and self.sender_thread.is_alive():
                        try:
                            self.sender_thread.join(timeout=1)
                        except RuntimeError as e:
                            print(f"RuntimeError joining sender_thread: {e}") 
                    if hasattr(self, 'receiver_thread') and self.receiver_thread.is_alive():
                        try:
                            self.receiver_thread.join(timeout=1)
                        except RuntimeError as e:
                            print(f"RuntimeError joining receiver_thread: {e}")
                del self.parent_client.active_calls[self.recipient]
            
            if self.recipient in self.parent_client.voice_call_windows:
                del self.parent_client.voice_call_windows[self.recipient]
            
            if self.window.winfo_exists():
                self.window.destroy()
            messagebox.showinfo("Call Ended", f"Call with {self.recipient} has ended.")

    def send_audio(self, target_ip, target_port, stop_event):
        print(f"Audio sender thread started. Target: {target_ip}:{target_port}")
        sending_socket = None
        stream_out = None
        try:
            sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self.p_audio is None:
                print("PyAudio not available in send_audio.")
                return # Cannot proceed without PyAudio
            stream_out = self.p_audio.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
            print("Microphone stream opened for sending.")
            while not stop_event.is_set():
                try:
                    data = stream_out.read(1024, exception_on_overflow=False)
                    sending_socket.sendto(data, (target_ip, target_port))
                except IOError as e:
                    if e.errno == pyaudio.paInputOverflowed:
                        print(f"Input overflow in send_audio: {e}. Continuing...")
                        # Potentially skip this frame or handle gracefully
                        continue
                    print(f"IOError in send_audio: {e}")
                    time.sleep(0.01) # Brief pause on other IOErrors
                except socket.error as se:
                    print(f"Socket error in send_audio: {se}")
                    break # Likely a connection issue, stop sending
                except Exception as e:
                    print(f"Unexpected error in send_audio loop: {e}")
                    break
        except pyaudio.PyAudioError as pae:
            print(f"PyAudioError in send_audio (e.g., device unavailable): {pae}")
            if not stop_event.is_set():
                 messagebox.showerror("Audio Error", f"Microphone error: {pae}")
        except Exception as e:
            print(f"Could not open microphone stream or other error in send_audio: {e}")
            if not stop_event.is_set():
                 messagebox.showerror("Audio Error", f"Failed to start microphone: {e}")
        finally:
            if stream_out:
                try:
                    if stream_out.is_active():
                        stream_out.stop_stream()
                    stream_out.close()
                except Exception as e:
                    print(f"Error closing output audio stream: {e}")
            if sending_socket:
                sending_socket.close()
            print(f"Audio sender thread for {target_ip}:{target_port} stopped.")

    def receive_audio(self, my_listen_port, stop_event):
        print(f"Audio receiver thread started. Listening on port: {my_listen_port}")
        receiving_socket = None
        stream_in = None
        try:
            receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiving_socket.bind(('0.0.0.0', my_listen_port))
            receiving_socket.settimeout(1.0)  # Timeout to allow checking stop_event
            print(f"Receiver socket bound to 0.0.0.0:{my_listen_port}")
            
            if self.p_audio is None:
                print("PyAudio not available in receive_audio.")
                return # Cannot proceed without PyAudio
            stream_in = self.p_audio.open(format=pyaudio.paInt16, channels=1, rate=44100, output=True, frames_per_buffer=1024)
            print("Speaker stream opened for receiving.")
            while not stop_event.is_set():
                try:
                    data, addr = receiving_socket.recvfrom(2048) # Increased buffer size slightly
                    stream_in.write(data)
                except socket.timeout:
                    continue # Normal timeout, check stop_event
                except IOError as e:
                    if e.errno == pyaudio.paOutputUnderflowed:
                        print(f"Output underflow in receive_audio: {e}. Continuing...")
                        # Potentially play silence or handle gracefully
                        continue
                    print(f"IOError in receive_audio: {e}")
                    time.sleep(0.01) # Brief pause on other IOErrors
                except socket.error as se:
                    print(f"Socket error in receive_audio: {se}")
                    break # Likely a connection issue, stop receiving
                except Exception as e:
                    print(f"Unexpected error receiving/playing audio: {e}")
                    break
        except socket.error as se:
            print(f"Error binding receiver socket on 0.0.0.0:{my_listen_port} - {se}")
            if not stop_event.is_set():
                messagebox.showerror("Network Error", f"Could not bind to port {my_listen_port} for voice call: {se}")
        except pyaudio.PyAudioError as pae:
            print(f"PyAudioError in receive_audio (e.g., device unavailable): {pae}")
            if not stop_event.is_set():
                messagebox.showerror("Audio Error", f"Speaker error: {pae}")
        except Exception as e:
            print(f"Could not open speaker stream or other error in receive_audio: {e}")
            if not stop_event.is_set():
                messagebox.showerror("Audio Error", f"Failed to start speaker: {e}")
        finally:
            if stream_in:
                try:
                    if stream_in.is_active():
                        stream_in.stop_stream()
                    stream_in.close()
                except Exception as e:
                    print(f"Error closing input audio stream: {e}")
            if receiving_socket:
                receiving_socket.close()
            print(f"Audio receiver thread for port {my_listen_port} stopped.")

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

        # Initialize PyAudio if not already done
        if self.p_audio is None:
            try:
                self.p_audio = pyaudio.PyAudio()
                print("PyAudio initialized.")
            except Exception as e:
                messagebox.showerror("Audio Initialization Error", f"Could not initialize audio system: {e}")
                # Potentially disable calling features or exit
                self.p_audio = None # Ensure it's None if failed

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
