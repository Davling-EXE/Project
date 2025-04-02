
import socket
from Protocol import *
import threading
from database import Database

"""
constants
"""

IP = '0.0.0.0'
PORT = 8820
MAX_PACKET = 1024


class Server:
    def __init__(self):
        self.server = None
        self.clients = {}
        self.user_sockets = {}
        self.db = Database()

    def send_user_list(self):
        """
        Sends the list of online users to all connected clients
        """
        online_users = list(self.clients.keys())
        for username, client in self.clients.items():
            client.send(create_msg("user_list", "server", username, ",".join(online_users)).encode())

    def send_private_message(self, msg_type, sender, recipient, content):
        """
        Sends a private message to a specific user
        """
        if recipient in self.clients:
            self.clients[recipient].send(create_msg(msg_type, sender, recipient, content).encode())

    def handle(self, client, username):
        """
        Handles messages from a client
        :param client: Client socket
        :param username: Username of the client
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
        Accepts new client connections and initializes their sessions
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
