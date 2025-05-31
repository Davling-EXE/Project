
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
PORT = 8820          # Server TCP port number for signaling
VOICE_PORT = 8821    # Server UDP port number for voice data (not directly used by server for routing, but good to define)
MAX_PACKET = 1024    # Maximum size of received packets


class Server:
    def __init__(self):
        """
        Initialize the server with empty client dictionaries and database connection.

        Attributes:
        clients: Dictionary mapping usernames to socket connections (TCP)
        user_sockets: Dictionary mapping socket objects to usernames (TCP)
        db: Database instance for persistent storage
        rsa: RSAEncryption instance for key exchange
        aes_keys: Dictionary mapping usernames to their AES keys for TCP messages
        user_groups: Cache of user groups
        active_calls: Dictionary to track active calls {caller: recipient} or {(user1, user2): call_details}
        user_udp_info: Dictionary to store UDP address {(ip, port)} for users in a call {username: (ip, port)}
        """
        self.server = None                # Main server TCP socket
        self.clients = {}                # Active clients {username: tcp_socket}
        self.user_sockets = {}           # Reverse lookup {tcp_socket: username}
        self.db = Database()             # Database connection
        self.rsa = RSAEncryption()
        self.aes_keys = {}               # {username: AESEncryption_instance_for_TCP}
        self.user_groups = {}            # Cache of user groups {username: [group_names]}
        self.active_calls = {}           # {(caller, recipient): {'caller_udp': (ip, port), 'recipient_udp': (ip, port), 'aes_key': bytes}}
        self.user_in_call = {}           # {username: (peer_username, role ('caller'/'recipient'))} to quickly check if user is busy
        self.client_public_keys = {} # {username: public_key_str}

    def send_user_list(self):
        """
        Broadcast the list of online users to all connected clients.

        This method is called whenever a user connects or disconnects
        to keep all clients updated with the current list of online users.

        The user list is sent as a comma-separated string of usernames.
        """
        online_users = list(self.clients.keys())
        for username, client in self.clients.items():
            if username in self.aes_keys: # Only send to fully connected and encrypted clients
                client.send(create_msg("user_list", "server", username, ",".join(online_users)).encode())

    def send_group_list(self, username):
        """
        Send the list of groups a user belongs to.
        """
        if username in self.clients:
            user_groups = self.db.get_user_groups(username)
            self.user_groups[username] = user_groups
            group_list = ",".join(user_groups)
            if username in self.aes_keys: # Ensure client is fully connected
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

    def handle_authenticated_client(self, client, username):
        """
        Handle all messages from an authenticated and connected client.

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
                elif msg_type == "aes_key": # Client sends its AES key encrypted with server's public key
                    if username in self.client_public_keys:
                        try:
                            aes_key_bytes = self.rsa.decrypt_with_private_key(bytes.fromhex(content))
                            self.aes_keys[username] = AESEncryption(key=aes_key_bytes)
                            print(f"AES key established with {username}")
                            # Now client is fully connected, send initial lists
                            self.send_user_list()
                            self.send_group_list(username)
                        except Exception as e:
                            print(f"Failed to decrypt AES key from {username}: {e}")
                            client.send(create_msg("error", "server", username, "AES key processing failed").encode())
                            # Consider disconnecting the client here
                    else:
                        print(f"Received AES key from {username} but no public key stored.")
                        client.send(create_msg("error", "server", username, "Public key not found for AES setup").encode())

                elif msg_type == "message":
                    if username not in self.aes_keys:
                        client.send(create_msg("error", "server", username, "Secure channel not established.").encode())
                        continue
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
                    if username not in self.aes_keys:
                        client.send(create_msg("error", "server", username, "Secure channel not established.").encode())
                        continue
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

                # Voice Call Handling
                elif msg_type == "call_request":
                    # sender is caller, recipient is callee, content is AES key for the call (hex)
                    callee = recipient
                    call_aes_key_hex = content
                    print(f"Call request from {sender} to {callee}")
                    if callee in self.clients:
                        if callee in self.user_in_call:
                            client.send(create_msg("call_busy", "server", sender, f"{callee} is already in a call.").encode())
                        else:
                            # Forward call request to callee
                            self.clients[callee].send(create_msg("call_request", sender, callee, call_aes_key_hex).encode())
                            # Tentatively mark users as engaging in a call setup
                            # self.user_in_call[sender] = (callee, 'caller_pending')
                            # self.user_in_call[callee] = (sender, 'recipient_pending')
                    else:
                        client.send(create_msg("error", "server", sender, f"User {callee} is not online.").encode())

                elif msg_type == "call_accept":
                    # sender is callee, recipient is original caller
                    caller = recipient
                    print(f"Call accept from {sender} to {caller}")
                    if caller in self.clients:
                        # AES key was sent by caller in initial request, receiver just accepts
                        # Store call information
                        call_key = tuple(sorted((caller, sender)))
                        self.active_calls[call_key] = {'caller': caller, 'recipient': sender, 'caller_udp': None, 'recipient_udp': None}
                        self.user_in_call[caller] = (sender, 'caller')
                        self.user_in_call[sender] = (caller, 'recipient')
                        self.clients[caller].send(create_msg("call_accept", sender, caller, "").encode())
                        print(f"Active call established between {caller} and {sender}")
                    else:
                        # Caller might have disconnected
                        self.clients[sender].send(create_msg("error", "server", sender, f"User {caller} is no longer online.").encode())
                        # Clean up if receiver was marked pending
                        # if sender in self.user_in_call and self.user_in_call[sender][1] == 'recipient_pending':
                        #     del self.user_in_call[sender]
                        # if caller in self.user_in_call and self.user_in_call[caller][1] == 'caller_pending':
                        #     del self.user_in_call[caller]

                elif msg_type == "call_reject":
                    caller = recipient
                    print(f"Call reject from {sender} to {caller}")
                    if caller in self.clients:
                        self.clients[caller].send(create_msg("call_reject", sender, caller, "").encode())
                    # Clean up pending state
                    # if sender in self.user_in_call and self.user_in_call[sender][1] == 'recipient_pending':
                    #     del self.user_in_call[sender]
                    # if caller in self.user_in_call and self.user_in_call[caller][1] == 'caller_pending':
                    #     del self.user_in_call[caller]

                elif msg_type == "udp_info":
                    # sender is the user sending their UDP port, recipient is 'server', content is UDP port
                    user_udp_port = content
                    peer_username = None
                    user_role = None
                    call_key_tuple = None

                    if sender in self.user_in_call:
                        peer_username, user_role = self.user_in_call[sender]
                        call_key_tuple = tuple(sorted((sender, peer_username)))

                    if call_key_tuple and call_key_tuple in self.active_calls and peer_username in self.clients:
                        client_ip = client.getpeername()[0]
                        user_udp_address = (client_ip, int(user_udp_port))
                        print(f"Received UDP info from {sender} ({user_role}): {user_udp_address}")

                        current_call_info = self.active_calls[call_key_tuple]
                        if user_role == 'caller':
                            current_call_info['caller_udp'] = user_udp_address
                        elif user_role == 'recipient':
                            current_call_info['recipient_udp'] = user_udp_address
                        else: # Should not happen if user_in_call is managed correctly
                            print(f"Error: {sender} has unknown role {user_role} in call with {peer_username}")
                            continue

                        # Check if both UDP infos are received
                        if current_call_info['caller_udp'] and current_call_info['recipient_udp']:
                            caller_name = current_call_info['caller']
                            recipient_name = current_call_info['recipient']

                            caller_udp_addr_str = f"{current_call_info['recipient_udp'][0]}:{current_call_info['recipient_udp'][1]}"
                            recipient_udp_addr_str = f"{current_call_info['caller_udp'][0]}:{current_call_info['caller_udp'][1]}"

                            # Send peer UDP info to both clients
                            self.clients[caller_name].send(create_msg("peer_udp_info", "server", caller_name, caller_udp_addr_str).encode())
                            self.clients[recipient_name].send(create_msg("peer_udp_info", "server", recipient_name, recipient_udp_addr_str).encode())
                            print(f"Relayed UDP info for call between {caller_name} and {recipient_name}")
                    else:
                        print(f"UDP info from {sender} but no active call or peer not found.")

                elif msg_type == "call_end":
                    # sender is the one ending the call, recipient is the other party
                    peer = recipient
                    print(f"Call end request from {sender} to {peer}")
                    call_key = tuple(sorted((sender, peer)))
                    if call_key in self.active_calls:
                        del self.active_calls[call_key]
                    if sender in self.user_in_call:
                        del self.user_in_call[sender]
                    if peer in self.user_in_call:
                        del self.user_in_call[peer]

                    if peer in self.clients:
                        self.clients[peer].send(create_msg("call_end", sender, peer, "").encode())
                    print(f"Call between {sender} and {peer} ended.")

            except socket.error as err:
                print(f"Error handling client {username}: {err}")
                # Clean up call state if user disconnects abruptly
                if username in self.user_in_call:
                    peer, _ = self.user_in_call[username]
                    del self.user_in_call[username]
                    call_key = tuple(sorted((username, peer)))
                    if call_key in self.active_calls:
                        del self.active_calls[call_key]
                    if peer in self.user_in_call:
                        del self.user_in_call[peer]
                    if peer in self.clients:
                         self.clients[peer].send(create_msg("call_end", username, peer, "Disconnected").encode())

                if username in self.clients:
                    del self.clients[username]
                if client in self.user_sockets:
                    del self.user_sockets[client]
                if username in self.aes_keys:
                    del self.aes_keys[username]
                if username in self.user_groups:
                    del self.user_groups[username]
                try:
                    client.close()
                except:
                    pass
                self.send_user_list()
                break

    def receive(self):
        """
        Accept new connections, handle authentication, and spawn handler threads for authenticated clients.
        """
        while True:
            client, address = self.server.accept()
            print(f"Connection attempt from {str(address)}")

            try:
                # Initial message should be login or register
                msg_type, username, _, content = parse_msg(client)
                # content is expected to be "password|client_public_key_string"
                
                password, client_public_key_str = content.split('-', 1)
                self.client_public_keys[username] = client_public_key_str # Store client's public key

                auth_success = False
                response_type = "error"
                response_content = "Authentication failed."

                if msg_type == "login":
                    success, message = self.db.authenticate_user(username, password)
                    if success:
                        auth_success = True
                        response_type = "login_success"
                        # Send server's public key as content for successful login
                        response_content = self.rsa.export_public_key().decode()
                    else:
                        response_content = message
                elif msg_type == "register":
                    success, message = self.db.register_user(username, password)
                    if success:
                        auth_success = True
                        response_type = "register_success"
                        # Send server's public key as content for successful registration
                        response_content = self.rsa.export_public_key().decode()
                    else:
                        response_content = message
                else:
                    response_content = "Invalid initial message type. Expected login or register."

                client.send(create_msg(response_type, "server", username, response_content).encode())

                if auth_success:
                    if username in self.clients:
                        # This case should ideally be handled by kicking the old session or denying new one
                        print(f"User {username} already logged in. Closing new connection.")
                        client.send(create_msg("error", "server", username, "User already logged in elsewhere.").encode())
                        client.close()
                        continue
                    
                    print(f"User {username} authenticated successfully.")
                    # Client will send AES key next, which is handled in handle_authenticated_client
                    self.clients[username] = client
                    self.user_sockets[client] = username
                    # Note: send_user_list and send_group_list are now called *after* AES key is established in handle_authenticated_client
                    
                    thread = threading.Thread(target=self.handle_authenticated_client, args=(client, username))
                    thread.start()
                else:
                    print(f"Authentication failed for {username}: {response_content}")
                    client.close()
                    if username in self.client_public_keys: # Clean up stored key if auth failed
                        del self.client_public_keys[username]

            except Exception as e:
                print(f"Error during initial connection/authentication with {str(address)}: {e}")
                try:
                    client.send(create_msg("error", "server", "unknown_user", "Server error during connection setup.").encode())
                except Exception:
                    pass # Client might already be closed
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