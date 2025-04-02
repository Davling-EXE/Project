
import socket
from Protocol import *
import threading
from database import Database

"""
Chat Server Application

This module implements a multi-threaded chat server that:
- Accepts and manages client connections
- Handles user authentication
- Routes messages between clients
- Maintains list of online users
- Persists chat messages in database

The server uses TCP sockets for communication and implements
a custom protocol for message handling.
"""

# Network configuration
IP = '0.0.0.0'        # Listen on all available interfaces
PORT = 8820          # Server port number
MAX_PACKET = 1024    # Maximum size of received packets


class Server:
    def __init__(self):
        """
        Initialize the chat server.
        
        Attributes:
            server: Main server socket for accepting connections
            clients: Dictionary mapping usernames to client sockets
            user_sockets: Dictionary mapping socket objects to usernames
            db: Database instance for persistent storage
        """
        self.server = None                # Main server socket
        self.clients = {}                # Active clients {username: socket}
        self.user_sockets = {}           # Reverse lookup {socket: username}
        self.db = Database()             # Database connection

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
            self.clients[recipient].send(create_msg(msg_type, sender, recipient, content).encode())

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
                        client.close()
                        self.send_user_list()
                    break
                elif msg_type == "message":
                    self.db.save_message(sender, recipient, content)
                    self.send_private_message(msg_type, sender, recipient, content)
            except socket.error as err:
                print(f"Error handling client {username}: {err}")
                if username in self.clients:
                    del self.clients[username]
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
                    
                    client.send(create_msg("connect", "server", username, "Connected to server").encode())
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
