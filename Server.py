
import socket
from Protocol import *
import threading

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
        self.online_users = []

    def send_private_message(self, message, recipient, sender):
        """
        sends a private message to a specific user
        :param message: message content
        :param recipient: recipient's username
        :param sender: sender's username
        :return: None
        """
        if sender in self.clients:
            if recipient in self.clients:
                # Send message to recipient
                self.clients[recipient].send(create_msg(message, recipient, sender).encode())
                # Send confirmation back to sender
                self.clients[sender].send(create_msg(message, recipient, sender).encode())
            else:
                # Notify sender that recipient is not available
                self.clients[sender].send(create_msg("User is not available", sender, "server").encode())

    def broadcast_online_users(self):
        """
        broadcasts the list of online users to all clients
        """
        for username in self.clients:
            # Create a list of online users excluding the current user
            other_users = [user for user in self.online_users if user != username]
            online_users = ", ".join(other_users) if other_users else "No other users online"
            self.clients[username].send(create_msg(f"online_users:{online_users}", username, "server").encode())

    def handle(self, client, username):
        """
        handles the client
        :param client: client socket
        :param username: client's username
        :return: None
        """
        while True:
            try:
                message, recipient, sender = get_msg(client)
                if message == "disconnect":
                    self.clients.pop(username)
                    self.online_users.remove(username)
                    client.close()
                    self.broadcast_online_users()
                else:
                    self.send_private_message(message, recipient, sender)
            except socket.error as err:
                print(err)
                if username in self.clients:
                    self.clients.pop(username)
                    self.online_users.remove(username)
                    self.broadcast_online_users()
                break

    def receive(self):
        """
        connects to a client then opens a thread to handles them
        :return: None
        """
        while True:
            client, address = self.server.accept()
            print(f"connected with {str(address)}")

            message, recipient, username = get_msg(client)

            if message == "connect" and username not in self.clients:
                self.clients[username] = client
                self.online_users.append(username)

                print(f"connected client: {username}")

                client.send(create_msg('Connected to server', username, "server").encode())
                self.broadcast_online_users()

                thread = threading.Thread(target=self.handle, args=(client, username))
                thread.start()
            else:
                client.send(create_msg('issue connecting', "server", "server").encode())
                client.close()

    def main(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((IP, PORT))
        self.server.listen()

        self.receive()


if __name__ == '__main__':
    Server = Server()
    Server.main()
