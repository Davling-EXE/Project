
import socket

SERVER_IP = "127.0.0.1"
PORT = 8820
MAX_PACKAGE = 1024


class Client:

    def __init__(self, ip, port, queue_size, max_package):
        self.ip = ip
        self.port = port
        self.queue_size = queue_size
        self.max_package = max_package
        self.client_list = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(self.queue_size)

    def recieve_client(self):
        self.client_list.append(self.server_socket.accept())
