
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
        self.clients = None
        self.nicknames = None
        self.rooms = None

    def broadcast(self, message, room, name):
        """
        sends the given message to all clients in a given room
        :param message:
        :param room:
        :param name:
        :return:
        """
        names = []
        for client in self.clients:
            index = self.clients.index(client)
            if self.rooms[index] == room:
                client.send(create_msg(message, room, name).encode())
                names.append(self.nicknames[index])
        for client in self.clients:
            index = self.clients.index(client)
            if self.rooms[index] == room:
                client.send(create_msg("name: " + ", ".join(names), "0", "server").encode())

    def handle(self, client):
        """
        handles the client
        :param client:
        :return:
        """
        while True:
            try:
                message, room, name = get_msg(client)
                if message == "disconnect":
                    index = self.clients.index(client)
                    self.clients.remove(client)
                    client.close()
                    self.broadcast(f"{self.nicknames.pop(index)} left the chat", self.rooms.pop(index),
                                   "server")
                else:
                    self.broadcast(message, room, name)
            except socket.error as err:
                print(err)
                break

    def recieve(self):
        """
        connects to a client then opens a thread to handles them
        :return:
        """
        while True:
            client, address = self.server.accept()
            print(f"connected with {str(address)}")

            message, room, name = get_msg(client)

            if message == "connect":
                self.clients.append(client)
                self.rooms.append(room)
                self.nicknames.append(name)

                print("connected to a client")

                client.send(create_msg('Connected to server', "0", "server").encode())

                self.broadcast(name + " has entered the chat", room, "server")

                thread = threading.Thread(target=self.handle, args=(client,))
                thread.start()
            else:
                client.send(create_msg('issue connecting', "0", "server").encode())
                client.close()

    def main(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((IP, PORT))
        self.server.listen()

        self.clients = []
        self.nicknames = []
        self.rooms = []

        self.recieve()


if __name__ == '__main__':
    Server = Server()
    Server.main()
