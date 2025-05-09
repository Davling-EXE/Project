
from typing import Optional, Dict, Any, Callable, List, Tuple
import socket
from Protocol import create_msg, parse_msg # Adjusted import
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
    def __init__(self) -> None:
        """
        Initialize the chat server.
        
        Attributes:
        server: Main server socket for accepting connections
        clients: Dictionary mapping usernames to client sockets
        user_sockets: Dictionary mapping socket objects to usernames
        db: Database instance for persistent storage
        """
        self.server: Optional[socket.socket] = None                # Main server socket
        self.clients: Dict[str, socket.socket] = {}                # Active clients {username: socket}
        self.user_sockets: Dict[socket.socket, str] = {}           # Reverse lookup {socket: username}
        self.db: Database = Database()             # Database connection
        self.rsa: RSAEncryption = RSAEncryption()
        self.aes_keys: Dict[str, AESEncryption] = {}
        self.active_calls: Dict[str, Dict[str, Dict[str, Any]]] = {}  # {caller: {recipient: {details...}}, ...}

    def send_user_list(self) -> None:
        """
        Broadcast the list of online users to all connected clients.
        
        This method is called whenever a user connects or disconnects
        to keep all clients updated with the current list of online users.
        
        The user list is sent as a comma-separated string of usernames.
        """
        online_users = list(self.clients.keys())
        for username, client in self.clients.items():
            client.send(create_msg("user_list", "server", username, ",".join(online_users)).encode())

    def send_private_message(self, msg_type: str, sender: str, recipient: str, content: str) -> None:
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

    def handle(self, client: socket.socket, username: str) -> None:
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
                        if username in self.aes_keys:
                            del self.aes_keys[username]
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
                elif msg_type == "call_request":
                    # content is caller_udp_port
                    caller_udp_port = content
                    if recipient in self.clients:
                        # Check if recipient is already in a call or being called by someone else
                        is_recipient_busy = any(r == recipient or c == recipient for c, details in self.active_calls.items() for r in details)
                        if is_recipient_busy:
                            client.send(create_msg("call_error", "server", sender, f"{recipient},is busy in another call").encode())
                        else:
                            print(f"Relaying call_request from {sender} (port {caller_udp_port}) to {recipient}")
                            self.clients[recipient].send(create_msg("call_request", sender, recipient, f"{sender},{caller_udp_port}").encode())
                            # Store pending call, sender is key, recipient and their socket is value
                            if sender not in self.active_calls:
                                self.active_calls[sender] = {}
                            self.active_calls[sender][recipient] = {'caller_socket': client, 'recipient_socket': self.clients[recipient], 'caller_udp_port': caller_udp_port, 'status': 'pending'}
                    else:
                        client.send(create_msg("call_error", "server", sender, f"{recipient},is not online").encode())
                elif msg_type == "call_accept":
                    # content is acceptor_udp_port
                    acceptor_udp_port = content
                    # recipient is the original caller
                    if recipient in self.clients and recipient in self.active_calls and sender in self.active_calls[recipient]:
                        print(f"Relaying call_accept from {sender} (port {acceptor_udp_port}) to {recipient}")
                        self.clients[recipient].send(create_msg("call_accept", sender, recipient, f"{sender},{acceptor_udp_port}").encode())
                        self.active_calls[recipient][sender]['recipient_udp_port'] = acceptor_udp_port
                        self.active_calls[recipient][sender]['status'] = 'active'
                    else:
                        # Original caller might have disconnected or cancelled
                        client.send(create_msg("call_error", "server", sender, f"{recipient},is no longer available or call was cancelled").encode())
                        # Clean up if original caller's entry exists but sender (acceptor) is not the expected one
                        if recipient in self.active_calls and sender in self.active_calls[recipient]:
                             del self.active_calls[recipient][sender]
                             if not self.active_calls[recipient]:
                                 del self.active_calls[recipient]
                elif msg_type == "call_reject":
                    # content is reason
                    reason = content
                    # recipient is the original caller
                    if recipient in self.clients and recipient in self.active_calls and sender in self.active_calls[recipient]:
                        print(f"Relaying call_reject from {sender} to {recipient}. Reason: {reason}")
                        self.clients[recipient].send(create_msg("call_reject", sender, recipient, f"{sender},{reason}").encode())
                        del self.active_calls[recipient][sender]
                        if not self.active_calls[recipient]:
                            del self.active_calls[recipient]
                    else:
                        # Original caller might have disconnected or call was already handled
                        print(f"Call reject from {sender} to {recipient} - original caller/call not found or already handled.")
                elif msg_type == "call_hangup":
                    # content is empty, sender is the one hanging up, recipient is the other party
                    print(f"Processing hangup from {sender} to {recipient}")
                    # Notify the other party
                    if recipient in self.clients:
                        self.clients[recipient].send(create_msg("call_hangup", sender, recipient, sender).encode())
                    
                    # Clean up active_calls for both sides of the call
                    call_cleaned = False
                    if sender in self.active_calls and recipient in self.active_calls[sender]:
                        del self.active_calls[sender][recipient]
                        if not self.active_calls[sender]:
                            del self.active_calls[sender]
                        call_cleaned = True
                    if recipient in self.active_calls and sender in self.active_calls[recipient]:
                        del self.active_calls[recipient][sender]
                        if not self.active_calls[recipient]:
                            del self.active_calls[recipient]
                        call_cleaned = True
                    if call_cleaned:
                        print(f"Cleaned up call state between {sender} and {recipient}")
                    else:
                        print(f"No active call state found to clean up for {sender} and {recipient} during hangup by {sender}")
            except socket.error as err:
                print(f"Error handling client {username}: {err}")
                if username in self.clients:
                    del self.clients[username]
                    if username in self.aes_keys:
                        del self.aes_keys[username]
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
            if msg_type == "connect":
                username = sender
                if username not in self.clients:
                    self.clients[username] = client
                    print(f"User {username} connected")
                    # Send server public key to client
                    client.send(create_msg("connect", "server", username, self.rsa.export_public_key().decode()).encode())
                    # Wait for AES key from client
                    aes_msg_type, aes_sender, aes_recipient, aes_content = parse_msg(client)
                    if aes_msg_type == "aes_key":
                        encrypted_aes = bytes.fromhex(aes_content)
                        aes_key = self.rsa.decrypt_with_private_key(encrypted_aes)
                        self.aes_keys[username] = AESEncryption(aes_key)
                    self.send_user_list()
                    thread = threading.Thread(target=self.handle, args=(client, username))
                    thread.start()
                else:
                    client.send(create_msg("error", "server", username, "Username already taken").encode())
                    client.close()
            else:
                client.send(create_msg("error", "server", "", "Invalid connection request").encode())
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
