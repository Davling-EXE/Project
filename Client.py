from tkinter import *
import socket
from Protocol import *
from tkinter import messagebox
import threading
from tkinter.scrolledtext import ScrolledText
import json
from cryptography.hazmat.primitives import serialization
from tkinter import ttk
import time

"""
constants
"""

SERVER_IP = "127.0.0.1"
PORT = 8820
MAX_PACKAGE = 4096

class Client:
    def __init__(self):
        self.server = None
        self.private_key = None
        self.public_key = None
        self.username = None
        self.current_chat = None  # Current chat (username or group_id)
        self.current_chat_type = None  # "private" or "group"
        self.chat_history = {}  # {username/group_id: [messages]}
        self.contacts = []  # List of usernames
        self.groups = []  # List of group objects
        self.root = None
        self.login_frame = None
        self.register_frame = None
        self.main_frame = None
        self.chat_frame = None
        
        # Initialize the GUI
        self.initialize_gui()
        
    def initialize_gui(self):
        """Initialize the main GUI window"""
        self.root = Tk()
        self.root.title("Secure Chat Application")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        
        # Create frames for different screens
        self.create_login_frame()
        self.create_register_frame()
        
        # Show login frame initially
        self.show_login_frame()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
        
    def create_login_frame(self):
        """Create the login screen"""
        self.login_frame = Frame(self.root)
        
        Label(self.login_frame, text="Secure Chat Login", font=("Arial", 18, "bold")).pack(pady=20)
        
        frame = Frame(self.login_frame)
        frame.pack(pady=10)
        
        Label(frame, text="Username:").grid(row=0, column=0, sticky=W, pady=5)
        self.login_username = Entry(frame, width=30)
        self.login_username.grid(row=0, column=1, pady=5)
        
        Label(frame, text="Password:").grid(row=1, column=0, sticky=W, pady=5)
        self.login_password = Entry(frame, width=30, show="*")
        self.login_password.grid(row=1, column=1, pady=5)
        
        button_frame = Frame(self.login_frame)
        button_frame.pack(pady=20)
        
        Button(button_frame, text="Login", width=10, command=self.login).pack(side=LEFT, padx=10)
        Button(button_frame, text="Register", width=10, command=self.show_register_frame).pack(side=LEFT)
        
        self.login_status = Label(self.login_frame, text="", fg="red")
        self.login_status.pack(pady=10)
        
    def create_register_frame(self):
        """Create the registration screen"""
        self.register_frame = Frame(self.root)
        
        Label(self.register_frame, text="Create New Account", font=("Arial", 18, "bold")).pack(pady=20)
        
        frame = Frame(self.register_frame)
        frame.pack(pady=10)
        
        Label(frame, text="Username:").grid(row=0, column=0, sticky=W, pady=5)
        self.register_username = Entry(frame, width=30)
        self.register_username.grid(row=0, column=1, pady=5)
        
        Label(frame, text="Password:").grid(row=1, column=0, sticky=W, pady=5)
        self.register_password = Entry(frame, width=30, show="*")
        self.register_password.grid(row=1, column=1, pady=5)
        
        Label(frame, text="Confirm Password:").grid(row=2, column=0, sticky=W, pady=5)
        self.register_confirm = Entry(frame, width=30, show="*")
        self.register_confirm.grid(row=2, column=1, pady=5)
        
        button_frame = Frame(self.register_frame)
        button_frame.pack(pady=20)
        
        Button(button_frame, text="Register", width=10, command=self.register).pack(side=LEFT, padx=10)
        Button(button_frame, text="Back to Login", width=15, command=self.show_login_frame).pack(side=LEFT)
        
        self.register_status = Label(self.register_frame, text="", fg="red")
        self.register_status.pack(pady=10)
        
    def create_main_frame(self):
        """Create the main chat interface"""
        self.main_frame = Frame(self.root)
        
        # Create a top bar with user info and logout button
        top_bar = Frame(self.main_frame, bg="#f0f0f0", height=40)
        top_bar.pack(fill=X, side=TOP)
        
        Label(top_bar, text=f"Logged in as: {self.username}", bg="#f0f0f0").pack(side=LEFT, padx=10)
        Button(top_bar, text="Logout", command=self.logout).pack(side=RIGHT, padx=10)
        
        # Create a paned window for contacts/groups and chat area
        paned = PanedWindow(self.main_frame, orient=HORIZONTAL)
        paned.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # Left panel for contacts and groups
        left_panel = Frame(paned, width=200)
        paned.add(left_panel, width=200)
        
        # Notebook for contacts and groups tabs
        notebook = ttk.Notebook(left_panel)
        notebook.pack(fill=BOTH, expand=True)
        
        # Contacts tab
        contacts_frame = Frame(notebook)
        notebook.add(contacts_frame, text="Contacts")
        
        # Add contact button
        Button(contacts_frame, text="Add Contact", command=self.show_add_contact_dialog).pack(fill=X, padx=5, pady=5)
        
        # Contacts list
        self.contacts_listbox = Listbox(contacts_frame, selectmode=SINGLE)
        self.contacts_listbox.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.contacts_listbox.bind("<Double-1>", self.on_contact_selected)
        
        # Groups tab
        groups_frame = Frame(notebook)
        notebook.add(groups_frame, text="Groups")
        
        # Create group button
        Button(groups_frame, text="Create Group", command=self.show_create_group_dialog).pack(fill=X, padx=5, pady=5)
        Button(groups_frame, text="Join Group", command=self.show_join_group_dialog).pack(fill=X, padx=5, pady=5)
        
        # Groups list
        self.groups_listbox = Listbox(groups_frame, selectmode=SINGLE)
        self.groups_listbox.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.groups_listbox.bind("<Double-1>", self.on_group_selected)
        
        # Right panel for chat
        self.chat_frame = Frame(paned)
        paned.add(self.chat_frame, width=600)
        
        # Initially show "No chat selected" message
        self.show_no_chat_selected()
        
    def show_no_chat_selected(self):
        """Show a message when no chat is selected"""
        # Clear the chat frame
        for widget in self.chat_frame.winfo_children():
            widget.destroy()
            
        # Show message
        Label(self.chat_frame, text="No chat selected", font=("Arial", 14)).pack(expand=True)
        
    def show_chat(self, chat_id, chat_type):
        """Show the chat interface for a contact or group"""
        self.current_chat = chat_id
        self.current_chat_type = chat_type
        
        # Clear the chat frame
        for widget in self.chat_frame.winfo_children():
            widget.destroy()
            
        # Chat header
        header_text = f"Chat with: {chat_id}" if chat_type == "private" else f"Group: {chat_id}"
        header = Label(self.chat_frame, text=header_text, font=("Arial", 12, "bold"), bg="#f0f0f0")
        header.pack(fill=X, padx=5, pady=5)
        
        # Chat messages area
        self.chat_messages = ScrolledText(self.chat_frame, wrap=WORD, state=DISABLED)
        self.chat_messages.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # Load chat history
        if chat_id in self.chat_history:
            self.display_chat_history(chat_id)
        
        # Message input area
        input_frame = Frame(self.chat_frame)
        input_frame.pack(fill=X, padx=5, pady=5)
        
        self.message_input = Entry(input_frame)
        self.message_input.pack(fill=X, side=LEFT, expand=True)
        self.message_input.bind("<Return>", lambda event: self.send_message())
        
        send_button = Button(input_frame, text="Send", command=self.send_message)
        send_button.pack(side=RIGHT, padx=5)
        
    def display_chat_history(self, chat_id):
        """Display the chat history in the messages area"""
        self.chat_messages.config(state=NORMAL)
        self.chat_messages.delete(1.0, END)
        
        for message in self.chat_history.get(chat_id, []):
            sender = message.get("sender", "Unknown")
            content = message.get("content", "")
            timestamp = message.get("timestamp", "")
            
            if timestamp:
                timestamp_str = f"[{timestamp}] "
            else:
                timestamp_str = ""
                
            self.chat_messages.insert(END, f"{timestamp_str}{sender}: {content}\n")
            
        self.chat_messages.config(state=DISABLED)
        self.chat_messages.see(END)
        
    def add_message_to_history(self, chat_id, sender, content):
        """Add a message to the chat history"""
        if chat_id not in self.chat_history:
            self.chat_history[chat_id] = []
            
        timestamp = time.strftime("%H:%M:%S")
        
        self.chat_history[chat_id].append({
            "sender": sender,
            "content": content,
            "timestamp": timestamp
        })
        
        # If this is the current chat, update the display
        if self.current_chat == chat_id:
            self.chat_messages.config(state=NORMAL)
            self.chat_messages.insert(END, f"[{timestamp}] {sender}: {content}\n")
            self.chat_messages.config(state=DISABLED)
            self.chat_messages.see(END)
            
    def send_message(self):
        """Send a message to the current chat"""
        if not self.current_chat or not self.message_input.get():
            return
            
        message = self.message_input.get()
        self.message_input.delete(0, END)
        
        try:
            if self.current_chat_type == "private":
                # Get recipient's public key
                recipient = self.current_chat
                
                # For now, send unencrypted (we'll add encryption later)
                self.server.send(create_msg(MSG_TYPE_PRIVATE, message, self.username, recipient).encode())
                
                # Add to chat history
                self.add_message_to_history(recipient, self.username, message)
                
            elif self.current_chat_type == "group":
                group_id = self.current_chat
                self.server.send(create_msg(MSG_TYPE_GROUP, message, self.username, group=group_id).encode())
                
                # Add to chat history
                self.add_message_to_history(group_id, self.username, message)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
            
    def show_login_frame(self):
        """Show the login frame"""
        if hasattr(self, 'main_frame') and self.main_frame:
            self.main_frame.pack_forget()
        if hasattr(self, 'register_frame') and self.register_frame:
            self.register_frame.pack_forget()
            
        self.login_frame.pack(fill=BOTH, expand=True)
        
    def show_register_frame(self):
        """Show the registration frame"""
        self.login_frame.pack_forget()
        self.register_frame.pack(fill=BOTH, expand=True)
        
    def show_main_frame(self):
        """Show the main chat interface"""
        self.login_frame.pack_forget()
        if hasattr(self, 'register_frame') and self.register_frame:
            self.register_frame.pack_forget()
            
        if not hasattr(self, 'main_frame') or not self.main_frame:
            self.create_main_frame()
            
        self.main_frame.pack(fill=BOTH, expand=True)
        
        # Refresh contacts and groups
        self.refresh_contacts()
        self.refresh_groups()
        
    def show_add_contact_dialog(self):
        """Show dialog to add a new contact"""
        dialog = Toplevel(self.root)
        dialog.title("Add Contact")
        dialog.geometry("300x150")
        dialog.resizable(False, False)
        
        Label(dialog, text="Enter username:").pack(pady=10)
        
        username_entry = Entry(dialog, width=30)
        username_entry.pack(pady=5)
        
        def add_contact():
            username = username_entry.get().strip()
            if username:
                if username not in self.contacts and username != self.username:
                    self.contacts.append(username)
                    self.refresh_contacts()
                    dialog.destroy()
                else:
                    Label(dialog, text="Contact already exists or invalid", fg="red").pack(pady=5)
            else:
                Label(dialog, text="Please enter a username", fg="red").pack(pady=5)
                
        Button(dialog, text="Add", command=add_contact).pack(pady=10)
        
    def show_create_group_dialog(self):
        """Show dialog to create a new group"""
        dialog = Toplevel(self.root)
        dialog.title("Create Group")
        dialog.geometry("300x150")
        dialog.resizable(False, False)
        
        Label(dialog, text="Enter group name:").pack(pady=10)
        
        group_name_entry = Entry(dialog, width=30)
        group_name_entry.pack(pady=5)
        
        def create_group():
            group_name = group_name_entry.get().strip()
            if group_name:
                try:
                    self.server.send(create_msg(MSG_TYPE_CREATE_GROUP, group_name, self.username).encode())
                    dialog.destroy()
                except Exception as e:
                    Label(dialog, text=f"Error: {str(e)}", fg="red").pack(pady=5)
            else:
                Label(dialog, text="Please enter a group name", fg="red").pack(pady=5)
                
        Button(dialog, text="Create", command=create_group).pack(pady=10)
        
    def show_join_group_dialog(self):
        """Show dialog to join an existing group"""
        dialog = Toplevel(self.root)
        dialog.title("Join Group")
        dialog.geometry("300x150")
        dialog.resizable(False, False)
        
        Label(dialog, text="Enter group ID:").pack(pady=10)
        
        group_id_entry = Entry(dialog, width=30)
        group_id_entry.pack(pady=5)
        
        def join_group():
            group_id = group_id_entry.get().strip()
            if group_id:
                try:
                    self.server.send(create_msg(MSG_TYPE_JOIN_GROUP, group_id, self.username).encode())
                    dialog.destroy()
                except Exception as e:
                    Label(dialog, text=f"Error: {str(e)}", fg="red").pack(pady=5)
            else:
                Label(dialog, text="Please enter a group ID", fg="red").pack(pady=5)
                
        Button(dialog, text="Join", command=join_group).pack(pady=10)
        
    def refresh_contacts(self):
        """Refresh the contacts list"""
        self.contacts_listbox.delete(0, END)
        for contact in sorted(self.contacts):
            self.contacts_listbox.insert(END, contact)
            
    def refresh_groups(self):
        """Refresh the groups list"""
        self.groups_listbox.delete(0, END)
        for group in self.groups:
            self.groups_listbox.insert(END, f"{group['id']}: {group['name']}")
            
    def on_contact_selected(self, event):
        """Handle contact selection"""
        selection = self.contacts_listbox.curselection()
        if selection:
            index = selection[0]
            contact = self.contacts_listbox.get(index)
            self.show_chat(contact, "private")
            
    def on_group_selected(self, event):
        """Handle group selection"""
        selection = self.groups_listbox.curselection()
        if selection:
            index = selection[0]
            group_text = self.groups_listbox.get(index)
            group_id = group_text.split(":")[0].strip()
            self.show_chat(group_id, "group")
            
    def login(self):
        """Handle login button click"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            self.login_status.config(text="Please enter username and password")
            return
            
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.connect((SERVER_IP, PORT))
            
            # Send login request
            self.server.send(create_msg(MSG_TYPE_LOGIN, password, username).encode())
            
            # Start receiving thread
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
            
            # Wait for response (handled in receive_messages)
            # The receive_messages thread will call show_main_frame on successful login
            
        except Exception as e:
            self.login_status.config(text=f"Connection error: {str(e)}")
            
    def register(self):
        """Handle register button click"""
        username = self.register_username.get().strip()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        
        if not username or not password:
            self.register_status.config(text="Please enter username and password")
            return
            
        if password != confirm:
            self.register_status.config(text="Passwords do not match")
            return
            
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.connect((SERVER_IP, PORT))
            
            # Send registration request
            self.server.send(create_msg(MSG_TYPE_REGISTER, password, username).encode())
            
            # Start receiving thread
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
            
        except Exception as e:
            self.register_status.config(text=f"Connection error: {str(e)}")
            
    def logout(self):
        """Handle logout"""
        try:
            if self.server:
                self.server.send(create_msg(MSG_TYPE_DISCONNECT, "", self.username).encode())
                self.server.close()
                
            # Reset client state
            self.server = None
            self.username = None
            self.current_chat = None
            self.current_chat_type = None
            self.chat_history = {}
            self.contacts = []
            self.groups = []
            
            # Show login screen
            self.show_login_frame()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error during logout: {str(e)}")
            
    def receive_messages(self):
        """Receive and process messages from the server"""
        while True:
            try:
                data = self.server.recv(MAX_PACKAGE).decode()
                if not data:
                    # Connection closed by server
                    messagebox.showerror("Connection Lost", "Server connection lost")
                    self.server.close()
                    self.show_login_frame()
                    break
                    
                message = parse_msg(data)
                if not message:
                    continue
                    
                msg_type = message.get("type")
                content = message.get("content")
                sender = message.get("sender")
                recipient = message.get("recipient")
                group = message.get("group")
                
                if msg_type == MSG_TYPE_SUCCESS:
                    if content == "Login successful":
                        self.username = self.login_username.get().strip()
                        self.show_main_frame()
                    elif content == "Registration successful":
                        messagebox.showinfo("Success", "Registration successful. Please login.")
                        self.show_login_frame()
                    elif content.startswith("Group") and "created" in content:
                        # Group created successfully
                        messagebox.showinfo("Success", content)
                        # Request updated group list
                        self.server.send(create_msg(MSG_TYPE_GROUP_LIST, "", self.username).encode())
                        
                elif msg_type == MSG_TYPE_ERROR:
                    if self.login_frame.winfo_ismapped():
                        self.login_status.config(text=content)
                    elif self.register_frame.winfo_ismapped():
                        self.register_status.config(text=content)
                    else:
                        messagebox.showerror("Error", content)
                        
                elif msg_type == MSG_TYPE_KEY_EXCHANGE:
                    # Store private key
                    self.private_key = content.encode()
                    
                    # Generate and send public key
                    private_key_obj = serialization.load_pem_private_key(
                        self.private_key,
                        password=None
                    )
                    public_key = private_key_obj.public_key()
                    public_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    self.public_key = public_pem
                    
                    # Send public key to server
                    self.server.send(create_msg(MSG_TYPE_KEY_EXCHANGE, public_pem.decode(), self.username).encode())
                    
                elif msg_type == MSG_TYPE_PRIVATE:
                    # Handle private message
                    if sender != self.username:
                        self.add_message_to_history(sender, sender, content)
                        
                        # If not the current chat, highlight it somehow
                        if self.current_chat != sender:
                            # For now, just show a message box
                            messagebox.showinfo("New Message", f"New message from {sender}")
                            
                elif msg_type == MSG_TYPE_GROUP:
                    # Handle group message
                    if sender != self.username:
                        self.add_message_to_history(group, sender, content)
                        
                        # If not the current chat, highlight it somehow
                        if self.current_chat != group:
                            # For now, just show a message box
                            messagebox.showinfo("New Group Message", f"New message in group {group}")
                            
                elif msg_type == MSG_TYPE_USER_LIST:
                    # Update online users list
                    online_users = json.loads(content)
                    # For now, we don't do anything with this
                    
                elif msg_type == MSG_TYPE_GROUP_LIST:
                    # Update groups list
                    self.groups = json.loads(content)
                    self.refresh_groups()
                    
            except Exception as e:
                print(f"Error receiving message: {str(e)}")
                break
                
    def on_closing(self):
        """Handle window closing"""
        try:
            if self.server:
                self.server.send(create_msg(MSG_TYPE_DISCONNECT, "", self.username).encode())
                self.server.close()
        except:
            pass
            
        self.root.destroy()


if __name__ == '__main__':
    client = Client()