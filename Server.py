import socket
import select
from Protocol import *
from Database import Database
import json

class Server:
    def __init__(self, ip="0.0.0.0", port=8820):
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.client_sockets = []
        self.messages_to_send = []
        self.clients = {}  # {client_socket: {"username": username, "private_key": key}}
        self.db = Database()
        self.user_keys = {}  # {username: public_key}
        
    def start(self):
        """Start the server"""
        print(f"Starting server on {self.ip}:{self.port}")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)
        print("Server is listening for connections...")
        
        while True:
            ready_to_read, ready_to_write, in_error = select.select(
                [self.server_socket] + self.client_sockets, 
                self.client_sockets, 
                []
            )
            
            for current_socket in ready_to_read:
                if current_socket is self.server_socket:
                    # New client connection
                    client_socket, client_address = self.server_socket.accept()
                    print(f"New connection from {client_address}")
                    self.client_sockets.append(client_socket)
                else:
                    # Data from existing client
                    try:
                        data = current_socket.recv(4096).decode()
                        if data:
                            self.handle_client_message(current_socket, data)
                        else:
                            # Client disconnected
                            self.handle_client_disconnect(current_socket)
                    except Exception as e:
                        print(f"Error handling client: {e}")
                        self.handle_client_disconnect(current_socket)
            
            # Send queued messages
            for message in self.messages_to_send:
                client_socket, data = message
                if client_socket in ready_to_write:
                    try:
                        client_socket.send(data.encode())
                        self.messages_to_send.remove(message)
                    except:
                        self.handle_client_disconnect(client_socket)
                        
    def handle_client_message(self, client_socket, data):
        """Handle a message from a client"""
        try:
            message = parse_msg(data)
            if not message:
                return
                
            msg_type = message.get("type")
            sender = message.get("sender")
            content = message.get("content")
            recipient = message.get("recipient")
            group = message.get("group")
            encrypted = message.get("encrypted", False)
            encrypted_data = message.get("encrypted_data")
            
            print(f"Received {msg_type} message from {sender}")
            
            if msg_type == MSG_TYPE_REGISTER:
                self.handle_register(client_socket, sender, content)
            elif msg_type == MSG_TYPE_LOGIN:
                self.handle_login(client_socket, sender, content)
            elif msg_type == MSG_TYPE_KEY_EXCHANGE:
                self.handle_key_exchange(client_socket, sender, content)
            elif msg_type == MSG_TYPE_CONNECT:
                self.handle_connect(client_socket, sender)
            elif msg_type == MSG_TYPE_DISCONNECT:
                self.handle_disconnect(client_socket)
            elif msg_type == MSG_TYPE_CHAT:
                self.handle_chat_message(client_socket, sender, content)
            elif msg_type == MSG_TYPE_PRIVATE:
                self.handle_private_message(client_socket, sender, recipient, content, encrypted, encrypted_data)
            elif msg_type == MSG_TYPE_GROUP:
                self.handle_group_message(client_socket, sender, group, content)
            elif msg_type == MSG_TYPE_CREATE_GROUP:
                self.handle_create_group(client_socket, sender, content)
            elif msg_type == MSG_TYPE_JOIN_GROUP:
                self.handle_join_group(client_socket, sender, content)
            elif msg_type == MSG_TYPE_LEAVE_GROUP:
                self.handle_leave_group(client_socket, sender, content)
            elif msg_type == MSG_TYPE_USER_LIST:
                self.handle_user_list(client_socket)
            elif msg_type == MSG_TYPE_GROUP_LIST:
                self.handle_group_list(client_socket, sender)
                
        except Exception as e:
            print(f"Error processing message: {e}")
            error_msg = create_msg(MSG_TYPE_ERROR, str(e), "server")
            self.messages_to_send.append((client_socket, error_msg))
            
    def handle_register(self, client_socket, username, password):
        """Handle user registration"""
        success = self.db.register_user(username, password)
        
        if success:
            response = create_msg(MSG_TYPE_SUCCESS, "Registration successful", "server")
            self.messages_to_send.append((client_socket, response))
        else:
            response = create_msg(MSG_TYPE_ERROR, "Username already exists", "server")
            self.messages_to_send.append((client_socket, response))
            
    def handle_login(self, client_socket, username, password):
        """Handle user login"""
        user = self.db.authenticate_user(username, password)
        
        if user:
            # Generate new key pair for this session
            private_key, public_key = generate_key_pair()
            
            # Store client information
            self.clients[client_socket] = {
                "username": username,
                "private_key": private_key
            }
            
            # Update user's public key in database
            self.db.update_user_key(username, public_key.decode())
            self.user_keys[username] = public_key
            
            response = create_msg(MSG_TYPE_SUCCESS, "Login successful", "server")
            self.messages_to_send.append((client_socket, response))
            
            # Send the user's private key
            key_msg = create_msg(MSG_TYPE_KEY_EXCHANGE, private_key.decode(), "server")
            self.messages_to_send.append((client_socket, key_msg))
        else:
            response = create_msg(MSG_TYPE_ERROR, "Invalid username or password", "server")
            self.messages_to_send.append((client_socket, response))
            
    def handle_key_exchange(self, client_socket, username, public_key):
        """Handle key exchange with client"""
        if client_socket in self.clients:
            # Store the user's public key
            self.user_keys[username] = public_key.encode()
            self.db.update_user_key(username, public_key)
            
            response = create_msg(MSG_TYPE_SUCCESS, "Key exchange successful", "server")
            self.messages_to_send.append((client_socket, response))
            
    def handle_connect(self, client_socket, username):
        """Handle client connection after authentication"""
        if client_socket in self.clients:
            # User is already authenticated
            response = create_msg(MSG_TYPE_SUCCESS, "Already connected", "server")
        else:
            # Check if user exists
            user = self.db.get_user_by_username(username)
            if user:
                self.clients[client_socket] = {"username": username}
                response = create_msg(MSG_TYPE_SUCCESS, "Connected to server", "server")
                
                # Notify other clients
                self.broadcast_user_list()
            else:
                response = create_msg(MSG_TYPE_ERROR, "User not found", "server")
                
        self.messages_to_send.append((client_socket, response))
        
    def handle_disconnect(self, client_socket):
        """Handle client disconnection"""
        if client_socket in self.clients:
            username = self.clients[client_socket]["username"]
            print(f"User {username} disconnected")
            
            # Remove client
            self.handle_client_disconnect(client_socket)
            
            # Notify other clients
            self.broadcast_user_list()
            
    def handle_client_disconnect(self, client_socket):
        """Clean up after client disconnection"""
        if client_socket in self.client_sockets:
            self.client_sockets.remove(client_socket)
            
        if client_socket in self.clients:
            del self.clients[client_socket]
            
        # Remove any pending messages for this client
        self.messages_to_send = [msg for msg in self.messages_to_send if msg[0] != client_socket]
        
        try:
            client_socket.close()
        except:
            pass
            
    def handle_chat_message(self, client_socket, sender, content):
        """Handle a public chat message"""
        # Save message to database
        self.db.save_message(sender, content=content)
        
        # Broadcast to all clients
        message = create_msg(MSG_TYPE_CHAT, content, sender)
        for client in self.client_sockets:
            if client != self.server_socket and client != client_socket:
                self.messages_to_send.append((client, message))
                
    def handle_private_message(self, client_socket, sender, recipient, content, encrypted, encrypted_data):
        """Handle a private message between users"""
        # Find recipient socket
        recipient_socket = None
        for client, info in self.clients.items():
            if info.get("username") == recipient:
                recipient_socket = client
                break
                
        # Save message to database
        self.db.save_message(sender, recipient, content=content)
        
        if recipient_socket:
            # Recipient is online, forward the message
            if encrypted and encrypted_data:
                # Forward encrypted message
                message = create_msg(MSG_TYPE_PRIVATE, content, sender, recipient, 
                                    encrypted_data=encrypted_data)
            else:
                # Forward unencrypted message
                message = create_msg(MSG_TYPE_PRIVATE, content, sender, recipient)
                
            self.messages_to_send.append((recipient_socket, message))
            
            # Send confirmation to sender
            confirm = create_msg(MSG_TYPE_SUCCESS, f"Message sent to {recipient}", "server")
            self.messages_to_send.append((client_socket, confirm))
        else:
            # Recipient is offline, store message for later delivery
            error = create_msg(MSG_TYPE_ERROR, f"User {recipient} is offline", "server")
            self.messages_to_send.append((client_socket, error))
            
    def handle_group_message(self, client_socket, sender, group_id, content):
        """Handle a group message"""
        try:
            group_id = int(group_id)
            
            # Save message to database
            self.db.save_message(sender, group_id=group_id, content=content)
            
            # Get group members
            members = self.db.get_group_members(group_id)
            
            # Forward message to all online group members
            message = create_msg(MSG_TYPE_GROUP, content, sender, group=group_id)
            for client, info in self.clients.items():
                if client != client_socket:
                    username = info.get("username")
                    if any(member["username"] == username for member in members):
                        self.messages_to_send.append((client, message))
                        
            # Send confirmation to sender
            confirm = create_msg(MSG_TYPE_SUCCESS, f"Message sent to group {group_id}", "server")
            self.messages_to_send.append((client_socket, confirm))
            
        except Exception as e:
            error = create_msg(MSG_TYPE_ERROR, f"Error sending group message: {str(e)}", "server")
            self.messages_to_send.append((client_socket, error))
            
    def handle_create_group(self, client_socket, creator, group_name):
        """Handle group creation"""
        try:
            group_id = self.db.create_group(group_name, creator)
            
            if group_id:
                response = create_msg(MSG_TYPE_SUCCESS, f"Group '{group_name}' created with ID {group_id}", "server", group=group_id)
                self.messages_to_send.append((client_socket, response))
            else:
                error = create_msg(MSG_TYPE_ERROR, "Failed to create group", "server")
                self.messages_to_send.append((client_socket, error))
                
        except Exception as e:
            error = create_msg(MSG_TYPE_ERROR, f"Error creating group: {str(e)}", "server")
            self.messages_to_send.append((client_socket, error))
            
    def handle_join_group(self, client_socket, username, group_id):
        """Handle a user joining a group"""
        try:
            group_id = int(group_id)
            user = self.db.get_user_by_username(username)
            
            if user:
                success = self.db.add_user_to_group(group_id, user["id"])
                
                if success:
                    response = create_msg(MSG_TYPE_SUCCESS, f"Joined group {group_id}", "server")
                    self.messages_to_send.append((client_socket, response))
                    
                    # Notify group members
                    members = self.db.get_group_members(group_id)
                    notification = create_msg(MSG_TYPE_GROUP, f"{username} joined the group", "server", group=group_id)
                    
                    for client, info in self.clients.items():
                        if client != client_socket:
                            client_username = info.get("username")
                            if any(member["username"] == client_username for member in members):
                                self.messages_to_send.append((client, notification))
                else:
                    error = create_msg(MSG_TYPE_ERROR, "Failed to join group", "server")
                    self.messages_to_send.append((client_socket, error))
            else:
                error = create_msg(MSG_TYPE_ERROR, "User not found", "server")
                self.messages_to_send.append((client_socket, error))
                
        except Exception as e:
            error = create_msg(MSG_TYPE_ERROR, f"Error joining group: {str(e)}", "server")
            self.messages_to_send.append((client_socket, error))
            
    def handle_leave_group(self, client_socket, username, group_id):
        """Handle a user leaving a group"""
        try:
            group_id = int(group_id)
            user = self.db.get_user_by_username(username)
            
            if user:
                success = self.db.remove_user_from_group(group_id, user["id"])
                
                if success:
                    response = create_msg(MSG_TYPE_SUCCESS, f"Left group {group_id}", "server")
                    self.messages_to_send.append((client_socket, response))
                    
                    # Notify group members
                    members = self.db.get_group_members(group_id)
                    notification = create_msg(MSG_TYPE_GROUP, f"{username} left the group", "server", group=group_id)
                    
                    for client, info in self.clients.items():
                        client_username = info.get("username")
                        if any(member["username"] == client_username for member in members):
                            self.messages_to_send.append((client, notification))
                else:
                    error = create_msg(MSG_TYPE_ERROR, "Failed to leave group", "server")
                    self.messages_to_send.append((client_socket, error))
            else:
                error = create_msg(MSG_TYPE_ERROR, "User not found", "server")
                self.messages_to_send.append((client_socket, error))
                
        except Exception as e:
            error = create_msg(MSG_TYPE_ERROR, f"Error leaving group: {str(e)}", "server")
            self.messages_to_send.append((client_socket, error))
            
    def handle_user_list(self, client_socket):
        """Send a list of online users to the client"""
        online_users = [info["username"] for info in self.clients.values()]
        response = create_msg(MSG_TYPE_USER_LIST, json.dumps(online_users), "server")
        self.messages_to_send.append((client_socket, response))
        
    def handle_group_list(self, client_socket, username):
        """Send a list of groups the user is a member of"""
        groups = self.db.get_user_groups(username)
        response = create_msg(MSG_TYPE_GROUP_LIST, json.dumps(groups), "server")
        self.messages_to_send.append((client_socket, response))
        
    def broadcast_user_list(self):
        """Broadcast the list of online users to all clients"""
        online_users = [info["username"] for info in self.clients.values()]
        message = create_msg(MSG_TYPE_USER_LIST, json.dumps(online_users), "server")
        
        for client in self.client_sockets:
            if client != self.server_socket:
                self.messages_to_send.append((client, message))


if __name__ == '__main__':
    server = Server()
    server.start()