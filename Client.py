
import socket

SERVER_IP = "127.0.0.1"
PORT = 8820
MAX_PACKAGE = 1024


class Client:

    def __init__(self, server_ip, port, max_package):
        self.server_ip = server_ip
        self.port = port
        self.max_package = max_package
        self.my_socket = socket.socket()
        self.my_socket.connect((self.server_ip, self.port))

    def send_message(self, message):
        self.my_socket.send(message.encode())

    def recieve_message(self):
        return self.my_socket.recv(self.max_package).decode()
