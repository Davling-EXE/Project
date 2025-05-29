
import socket
from Protocol import *
import threading
from database import Database
from Encryption import RSAEncryption, AESEncryption

"""Chat Server Application

This module implements a multi-threaded chat server that:
- Accepts and manages client connections using thread-safe socket operations
- Handles user authentication and session management
- Routes private messages between connected clients
- Maintains real-time list of online users
- Persists chat messages in SQLite database
- Implements error handling and connection recovery

Threading Model:
- Main thread: Accepts new connections and spawns handler threads
- Client threads: One per connected client, handles message processing
- Database operations: Thread-safe using connection pooling

Error Handling:
- Socket errors: Graceful disconnection and resource cleanup
- Database errors: Transaction rollback and connection recovery
- Protocol errors: Client notification and session termination

The server uses TCP sockets for reliable message delivery and implements
a custom protocol for structured message handling.
"""

# Network configuration
IP = '0.0.0.0'        # Listen on all available interfaces
PORT = 8820          # Server port number
MAX_PACKET = 1024    # Maximum size of received packets


class Server:
    def __init__(self):
        """
        Initialize the server with empty client dictionaries and database connection.

        Attributes:
        clients: Dictionary mapping usernames to socket connections
        user_sockets: Dictionary mapping socket objects to usernames
        db: Database instance for persistent storage
        """
        self.server = None                # Main server socket
        self.clients = {}                # Active clients {username: socket}
        self.user_sockets = {}           # Reverse lookup {socket: username}
        self.active_calls = {}           # Active voice calls {caller: recipient}
        self.db = Database()             # Database connection
        self.rsa = RSAEncryption()
        self.aes_keys = {}
        self.user_groups = {}            # Cache of user groups {username: [group_names]}

    def send_user_list(self):
        """
        Broadcast the list of online users to all connected clients.

        This method is called whenever a user connects or disconnects
        to keep all clients updated with the current list of online users.

        The user list is sent as a comma-separated string of usernames.
        """
        online_users = list(self.clients.keys())
        for username, client in self.clients.items():
            client.send(create_msg("user_list", "server", username, ",".join(online_users)).encode())

    def send_group_list(self, username):
        """
        Send the list of groups a user belongs to.
        """
        if username in self.clients:
            user_groups = self.db.get_user_groups(username)
            self.user_groups[username] = user_groups
            group_list = ",".join(user_groups)
            self.clients[username].send(create_msg("group_list", "server", username, group_list).encode())

    def send_group_message(self, group_name, sender, content):
        """
        Broadcast a message to all members of a group who are currently online.
        """
        group_members = self.db.get_group_members(group_name)
        for member in group_members:
            if member in self.clients and member != sender:
                if member in self.aes_keys:
                    encrypted = self.aes_keys[member].encrypt(content.encode()).hex()
                else:
                    encrypted = content
                self.clients[member].send(create_msg("group_message", sender, group_name, encrypted).encode())

    def send_private_message(self, msg_type, sender, recipient, content):
        """
        Route a message to a specific user.

        Args:
            msg_type (str): Type of message being sent
            sender (str): Username of message sender
            recipient (str): Username of message recipient
            content (str): Message content

        The message is only sent if the recipient is currently online.
        """
        if recipient in self.clients:
            if sender in self.aes_keys and recipient in self.aes_keys:
                encrypted = self.aes_keys[recipient].encrypt(content.encode()).hex()
            else:
                encrypted = content
            self.clients[recipient].send(create_msg(msg_type, sender, recipient, encrypted).encode())

    def handle(self, client, username):
        """
        Handle all messages from a connected client.

        This method runs in a separate thread for each client and:
        - Processes incoming messages
        - Routes messages to appropriate recipients
        - Handles client disconnection
        - Updates online user list when client disconnects

        Args:
            client (socket): Client's socket connection
            username (str): Client's username
        """
        while True:
            try:
                msg_type, sender, recipient, content = parse_msg(client)
                if msg_type == "disconnect" or msg_type == "error":
                    if username in self.clients:
                        del self.clients[username]
                        if client in self.user_sockets:
                            del self.user_sockets[client]
                        if username in self.aes_keys:
                            del self.aes_keys[username]
                        if username in self.user_groups:
                            del self.user_groups[username]
                        client.close()
                        self.send_user_list()
                    break
                elif msg_type == "message":
                    if username in self.aes_keys:
                        try:
                            decrypted = self.aes_keys[username].decrypt(bytes.fromhex(content)).decode()
                        except Exception:
                            decrypted = "[Decryption failed]"
                    else:
                        decrypted = content
                    self.db.save_message(sender, recipient, decrypted)
                    self.send_private_message(msg_type, sender, recipient, decrypted)
                elif msg_type == "group_message":
                    group_name = recipient
                    if username in self.aes_keys:
                        try:
                            decrypted = self.aes_keys[username].decrypt(bytes.fromhex(content)).decode()
                        except Exception:
                            decrypted = "[Decryption failed]"
                    else:
                        decrypted = content
                    self.db.save_group_message(group_name, sender, decrypted)
                    self.send_group_message(group_name, sender, decrypted)
                elif msg_type == "call_request":
                    # Handle voice call request
                    if recipient in self.clients:
                        # Check if recipient is already in a call
                        if recipient in self.active_calls.values() or recipient in self.active_calls:
                            error_msg = create_msg("error", "server", sender, f"{recipient} is already in a call")
                            client.send(error_msg.encode())
                        else:
                            # Forward call request to recipient
                            call_msg = create_msg("call_request", sender, recipient, "")
                            self.clients[recipient].send(call_msg.encode())
                    else:
                        error_msg = create_msg("error", "server", sender, f"{recipient} is not online")
                        client.send(error_msg.encode())
                elif msg_type == "call_accept":
                    # Handle call acceptance
                    if recipient in self.clients:
                        # Establish call connection
                        self.active_calls[recipient] = sender
                        self.active_calls[sender] = recipient
                        
                        # Notify both parties
                        accept_msg = create_msg("call_accept", sender, recipient, "")
                        self.clients[recipient].send(accept_msg.encode())
                    else:
                        error_msg = create_msg("error", "server", sender, f"{recipient} is not online")
                        client.send(error_msg.encode())
                elif msg_type == "call_decline":
                    # Handle call decline
                    if recipient in self.clients:
                        decline_msg = create_msg("call_decline", sender, recipient, "")
                        self.clients[recipient].send(decline_msg.encode())
                elif msg_type == "call_end":
                    # Handle call termination
                    if sender in self.active_calls:
                        call_partner = self.active_calls[sender]
                        # Remove call from active calls
                        del self.active_calls[sender]
                        if call_partner in self.active_calls:
                            del self.active_calls[call_partner]
                        
                        # Notify call partner
                        if call_partner in self.clients:
                            end_msg = create_msg("call_end", sender, call_partner, "")
                            self.clients[call_partner].send(end_msg.encode())
                elif msg_type == "voice_data":
                    # Handle voice data transmission
                    if sender in self.active_calls and recipient == self.active_calls[sender]:
                        if recipient in self.clients:
                            # Forward voice data to call partner
                            voice_msg = create_msg("voice_data", sender, recipient, content)
                            self.clients[recipient].send(voice_msg.encode())
                    else:
                        error_msg = create_msg("error", "server", sender, "No active call with this user")
                        client.send(error_msg.encode())
                elif msg_type == "create_group":
                    group_name = content
                    success, message = self.db.create_group(group_name, username)
                    if success:
                        self.send_group_list(username)
                        client.send(create_msg("info", "server", username, f"Group '{group_name}' created successfully").encode())
                    else:
                        client.send(create_msg("error", "server", username, message).encode())
                elif msg_type == "join_group":
                    group_name = content
                    success, message = self.db.join_group(group_name, username)
                    if success:
                        self.send_group_list(username)
                        client.send(create_msg("info", "server", username, f"Joined group '{group_name}' successfully").encode())
                    else:
                        client.send(create_msg("error", "server", username, message).encode())
            except socket.error as err:
                print(f"Error handling client {username}: {err}")
                if username in self.clients:
                    del self.clients[username]
                if client in self.user_sockets:
                    del self.user_sockets[client]
                if username in self.aes_keys:
                    del self.aes_keys[username]
                if username in self.user_groups:
                    del self.user_groups[username]
                # End any active calls
                if username in self.active_calls:
                    call_partner = self.active_calls[username]
                    del self.active_calls[username]
                    if call_partner in self.active_calls:
                        del self.active_calls[call_partner]
                    
                    # Notify call partner that call ended
                    if call_partner in self.clients:
                        end_msg = create_msg("call_end", username, call_partner, "")
                        self.clients[call_partner].send(end_msg.encode())
                try:
                    client.close()
                except:
                    pass
                self.send_user_list()
                break

    def receive(self):
        """
        Accept and handle new client connections.

        This is the main server loop that:
        - Accepts new socket connections
        - Validates connection requests
        - Initializes client sessions
        - Spawns client handler threads

        The method runs indefinitely until the server is stopped.
        """
        while True:
            client, address = self.server.accept()
            print(f"New connection from {str(address)}")
            msg_type, sender, recipient, content = parse_msg(client)
            print(f"Server received: {msg_type}, {sender}, {recipient}, {content}")

            if msg_type == "connect":
                username = sender
                if username not in self.clients:
                    self.clients[username] = client
                    self.user_sockets[client] = username  # Add reverse mapping
                    print(f"User {username} connected")
                    # Send server public key to client
                    response_msg = create_msg("connect", "server", username, self.rsa.export_public_key().decode())
                    print(f"Server sending: {response_msg}")
                    client.send(response_msg.encode())

                    # Wait for AES key from client
                    print("Waiting for AES key from client...")
                    aes_msg_type, aes_sender, aes_recipient, aes_content = parse_msg(client)
                    print(f"Server received AES: {aes_msg_type}, {aes_sender}, {aes_recipient}, {aes_content}")

                    if aes_msg_type == "aes_key":
                        try:
                            encrypted_aes = bytes.fromhex(aes_content)
                            aes_key = self.rsa.decrypt_with_private_key(encrypted_aes)
                            self.aes_keys[username] = AESEncryption(aes_key)
                            print(f"AES key established for {username}")
                        except Exception as e:
                            print(f"Error setting up AES key: {e}")

                    self.send_user_list()
                    self.send_group_list(username)
                    thread = threading.Thread(target=self.handle, args=(client, username))
                    thread.start()
                else:
                    error_msg = create_msg("error", "server", username, "Username already taken")
                    print(f"Server sending error: {error_msg}")
                    client.send(error_msg.encode())
                    client.close()
            elif msg_type == "error":
                print(f"Client sent error: {content}")
                client.close()
            else:
                error_msg = create_msg("error", "server", "", "Invalid connection request")
                print(f"Server sending error: {error_msg}")
                client.send(error_msg.encode())
                client.close()

    def main(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((IP, PORT))
        self.server.listen()
        print(f"Server started on {IP}:{PORT}")

        self.receive()


if __name__ == '__main__':
    Server = Server()
    Server.main()
