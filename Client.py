
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
        self.main_window = None    # Main application window
        self.db = Database()       # Database connection
        self.rsa = RSAEncryption()
        self.aes = None
        self.peer_public_keys = {}
        self.p_audio = None  # PyAudio instance for voice calls
        self.active_calls = {}  # To store active call data {recipient: CallData}
        self.voice_call_windows = {} # To store voice call window instances {recipient: VoiceCallWindow}

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
                elif msg_type == "call_request": # Incoming call request
                    # content should be "caller_username,caller_udp_port"
                    caller_username, caller_udp_port_str = content.split(',')
                    caller_udp_port = int(caller_udp_port_str)
                    if messagebox.askyesno("Incoming Call", f"{caller_username} is calling you. Accept?"):
                        my_udp_port = self.find_available_udp_port()
                        if not my_udp_port:
                            messagebox.showerror("Call Error", "No available UDP port to accept the call.")
                            self.server.send(create_msg("call_reject", self.username, caller_username, "No available port").encode())
                            return
                        self.active_calls[caller_username] = {'status': 'accepting', 'my_udp_port': my_udp_port, 'peer_udp_port': caller_udp_port, 'stop_event': threading.Event()}
                        self.server.send(create_msg("call_accept", self.username, caller_username, str(my_udp_port)).encode())
                        self.open_voice_call_window(caller_username, peer_ip=SERVER_IP, peer_udp_port=caller_udp_port, my_udp_port=my_udp_port, is_caller=False)
                    else:
                        self.server.send(create_msg("call_reject", self.username, caller_username, "Call rejected by user").encode())
                elif msg_type == "call_accept": # Your call was accepted
                    # content should be "acceptor_username,acceptor_udp_port"
                    acceptor_username, acceptor_udp_port_str = content.split(',')
                    acceptor_udp_port = int(acceptor_udp_port_str)
                    if acceptor_username in self.active_calls and self.active_calls[acceptor_username]['status'] == 'initiating':
                        self.active_calls[acceptor_username]['peer_udp_port'] = acceptor_udp_port
                        self.active_calls[acceptor_username]['status'] = 'accepted'
                        messagebox.showinfo("Call Accepted", f"{acceptor_username} accepted your call.")
                        my_udp_port = self.active_calls[acceptor_username]['my_udp_port']
                        self.open_voice_call_window(acceptor_username, peer_ip=SERVER_IP, peer_udp_port=acceptor_udp_port, my_udp_port=my_udp_port, is_caller=True)
                        # The VoiceCallWindow's __init__ or a method within it should now start audio streams
                        if acceptor_username in self.voice_call_windows:
                            self.voice_call_windows[acceptor_username].status_label.config(text=f"Call with {acceptor_username} active.")
                            self.voice_call_windows[acceptor_username].start_audio_streams()
                    else:
                        print(f"Received call_accept from {acceptor_username} but no pending call found or wrong state.")
                elif msg_type == "call_reject":
                    # content is "rejector_username,reason"
                    rejector_username, reason = content.split(',', 1)
                    messagebox.showinfo("Call Rejected", f"{rejector_username} rejected your call. Reason: {reason}")
                    if rejector_username in self.active_calls:
                        self.active_calls[rejector_username]['stop_event'].set() # Should not be needed if streams not started
                        del self.active_calls[rejector_username]
                    if rejector_username in self.voice_call_windows:
                        self.voice_call_windows[rejector_username].window.destroy()
                        del self.voice_call_windows[rejector_username]
                elif msg_type == "call_hangup":
                    # content is "hangupper_username"
                    hangupper_username = content
                    messagebox.showinfo("Call Ended", f"{hangupper_username} ended the call.")
                    if hangupper_username in self.active_calls:
                        self.active_calls[hangupper_username]['stop_event'].set()
                        # Ensure threads are joined if they were started
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
                elif msg_type == "call_error": # General call error from server
                    # content is "other_user,error_message"
                    other_user, error_message = content.split(',',1)
                    messagebox.showerror("Call Error", f"Call error with {other_user}: {error_message}")
                    if other_user in self.active_calls:
                        self.active_calls[other_user]['stop_event'].set()
                        del self.active_calls[other_user]
                    if other_user in self.voice_call_windows:
                        self.voice_call_windows[other_user].window.destroy()
                        del self.voice_call_windows[other_user]

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

    def find_available_udp_port(self, start_port=50000, end_port=50100):
        for port in range(start_port, end_port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("0.0.0.0", port))
                s.close()
                return port
            except socket.error:
                continue
        return None

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
        def __init__(self, parent_client, username, recipient, peer_ip, peer_udp_port, my_udp_port, is_caller):
            self.parent_client = parent_client
            self.username = username
            self.recipient = recipient
            self.peer_ip = peer_ip if peer_ip else SERVER_IP # Assume server IP if peer_ip not specified (for local testing)
            self.peer_udp_port = peer_udp_port
            self.my_udp_port = my_udp_port
            self.is_caller = is_caller
            self.stop_event = self.parent_client.active_calls[recipient]['stop_event']

            self.window = Toplevel()
            self.window.title(f"Voice Call with {recipient}")
            self.window.geometry(parent_client.get_window_position(300, 200))
            self.window.minsize(250, 150)
            self.window.protocol("WM_DELETE_WINDOW", self.hang_up_call)

            self.status_label = Label(self.window, text=f"Connecting to {recipient}...", font=('Segoe UI', '10'))
            self.status_label.pack(pady=20)

            self.hang_up_button = Button(self.window, text="Hang Up", font=('Segoe UI', '10'), 
                                         command=self.hang_up_call, bg="#f44336", fg="white")
            self.hang_up_button.pack(pady=10)

            if self.parent_client.p_audio is None:
                messagebox.showerror("Audio Error", "PyAudio not initialized.")
                self.window.destroy()
                return
            
            if self.my_udp_port and self.peer_udp_port:
                self.status_label.config(text=f"Call with {recipient} active.")
                self.start_audio_streams()
            elif is_caller:
                self.status_label.config(text=f"Calling {recipient}...")
            else: # is receiver, waiting for caller's port
                self.status_label.config(text=f"Incoming call from {recipient}...")

        def start_audio_streams(self):
            if not self.parent_client.active_calls[self.recipient].get('audio_started', False):
                print(f"Starting audio: Me ({self.my_udp_port}) -> {self.recipient} ({self.peer_ip}:{self.peer_udp_port})")
                self.sender_thread = threading.Thread(target=self.parent_client.send_audio, 
                                                      args=(self.peer_ip, self.peer_udp_port, self.stop_event))
                self.receiver_thread = threading.Thread(target=self.parent_client.receive_audio, 
                                                        args=(self.my_udp_port, self.stop_event))
                self.sender_thread.daemon = True
                self.receiver_thread.daemon = True
                self.sender_thread.start()
                self.receiver_thread.start()
                self.parent_client.active_calls[self.recipient]['audio_started'] = True
                self.status_label.config(text=f"Call with {self.recipient} active.")
            else:
                print("Audio streams already started for this call.")

        def hang_up_call(self):
            print(f"Hanging up call with {self.recipient}")
            if self.recipient in self.parent_client.active_calls:
                self.parent_client.active_calls[self.recipient]['stop_event'].set()
                # Notify server
                self.parent_client.server.send(create_msg("call_hangup", self.parent_client.username, self.recipient, "").encode())
                # Wait for threads to finish if they were started
                if self.parent_client.active_calls[self.recipient].get('audio_started', False):
                    if hasattr(self, 'sender_thread') and self.sender_thread.is_alive():
                        self.sender_thread.join(timeout=1)
                    if hasattr(self, 'receiver_thread') and self.receiver_thread.is_alive():
                        self.receiver_thread.join(timeout=1)
                del self.parent_client.active_calls[self.recipient]
            
            if self.recipient in self.parent_client.voice_call_windows:
                del self.parent_client.voice_call_windows[self.recipient]
            self.window.destroy()
            messagebox.showinfo("Call Ended", f"Call with {self.recipient} has ended.")

    def send_audio(self, target_ip, target_port, stop_event):
        print(f"Audio sender thread started. Target: {target_ip}:{target_port}")
        sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stream_out = None
        try:
            stream_out = self.p_audio.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
            print("Microphone stream opened for sending.")
            while not stop_event.is_set():
                try:
                    data = stream_out.read(1024, exception_on_overflow=False)
                    sending_socket.sendto(data, (target_ip, target_port))
                except IOError as e:
                    print(f"IOError in send_audio: {e}")
                    time.sleep(0.01)
                except Exception as e:
                    print(f"Error in send_audio loop: {e}")
                    break
        except Exception as e:
            print(f"Could not open microphone stream or error in send_audio: {e}")
            if not stop_event.is_set(): # Only show error if not intentionally stopped
                 messagebox.showerror("Audio Error", f"Failed to start microphone: {e}")
        finally:
            if stream_out:
                try:
                    stream_out.stop_stream()
                    stream_out.close()
                except Exception as e:
                    print(f"Error closing output stream: {e}")
            sending_socket.close()
            print(f"Audio sender thread for {target_ip}:{target_port} stopped.")

    def receive_audio(self, my_listen_port, stop_event):
        print(f"Audio receiver thread started. Listening on port: {my_listen_port}")
        receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stream_in = None
        try:
            receiving_socket.bind(('0.0.0.0', my_listen_port))
            receiving_socket.settimeout(1.0)  # Timeout to allow checking stop_event
            print(f"Receiver socket bound to 0.0.0.0:{my_listen_port}")
        except Exception as e:
            print(f"Error binding receiver socket on 0.0.0.0:{my_listen_port} - {e}")
            if not stop_event.is_set():
                messagebox.showerror("Network Error", f"Could not bind to port {my_listen_port} for voice call: {e}")
            return

        try:
            stream_in = self.p_audio.open(format=pyaudio.paInt16, channels=1, rate=44100, output=True, frames_per_buffer=1024)
            print("Speaker stream opened for receiving.")
            while not stop_event.is_set():
                try:
                    data, addr = receiving_socket.recvfrom(1024 * 1 * 2)
                    stream_in.write(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving/playing audio: {e}")
                    time.sleep(0.01)
        except Exception as e:
            print(f"Could not open speaker stream or error in receive_audio: {e}")
            if not stop_event.is_set():
                messagebox.showerror("Audio Error", f"Failed to start speaker: {e}")
        finally:
            if stream_in:
                try:
                    stream_in.stop_stream()
                    stream_in.close()
                except Exception as e:
                    print(f"Error closing input stream: {e}")
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
