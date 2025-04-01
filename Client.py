
from tkinter import *
import socket
from Protocol import *
from tkinter import messagebox
import threading
from tkinter.scrolledtext import ScrolledText

"""
constants
"""

SERVER_IP = "127.0.0.1"
PORT = 8820
MAX_PACKAGE = 1024
ROOT = Tk()
ROOT.title("User Identification")


class Client:

    def __init__(self):
        self.server = None
        self.user_box = None
        self.chat_box = None
        self.send_input = None
        self.top = None
        self.names = None
        self.name_input = None
        self.r = None

    def connect(self):
        """
        connects to the server
        :return:
        """
        try:
            self.server = socket.socket()
            self.server.connect((SERVER_IP, PORT))

            self.server.send(create_msg("connect", self.r.get(), self.name_input.get()).encode())

            messagebox.showinfo("Connected successfully", "connected to room " + self.r.get() +
                                " with the username " + self.name_input.get())

            self.open_chat()

        except socket.error as err:
            messagebox.showerror("an error occurred while trying to connect to the server", err)

    def recieve(self):
        """
        this takes care of receiving messages from the server
        :return:
        """
        while True:
            try:
                message, room, name = get_msg(self.server)
                if message == "issue connecting" and room == "0" and name == "server":
                    self.top.destroy()
                elif message[:6] == "name: " and room == "0" and name == "server":
                    names = message[6:].split(", ")
                    self.user_box.delete("1.0", "end")
                    for name in names:
                        self.user_box.insert(END, name + "\n")
                elif room == self.r.get():
                    self.chat_box.insert(END, name + ": " + message + "\n")
                    self.chat_box.see(END)
                elif message == "Connected to server" and room == "0" and name == "server":
                    self.chat_box.insert(END, name + ": " + message + "\n")
                    self.chat_box.see(END)

            except socket.error as err:
                messagebox.showerror("an error occurred", err)
                self.server.close()
                self.top.destroy()
                break

    def write(self):
        """
        sends message to server
        :return:
        """
        self.server.send(create_msg(self.send_input.get(), self.r.get(), self.name_input.get()).encode())

    def exit_chat(self):
        """
        leaves the chat
        :return:
        """
        self.server.send(create_msg("disconnect", self.r.get(), self.name_input.get()).encode())
        self.top.destroy()

    def open_chat(self):
        """
        opens the chat gui
        :return:
        """

        self.top = Toplevel()

        self.top.title("room " + self.r.get() + ": " + self.name_input.get())
        self.user_box = ScrolledText(self.top, width=20, height=25, state=NORMAL, bd=8)
        self.chat_box = ScrolledText(self.top, width=80, height=25, state=NORMAL, bd=8)
        self.send_input = Entry(self.top, width=80, bd=8)
        send_button = Button(self.top, width=10, height=1, bd=8, text="Send", font=('Segoe UI', '18'),
                             command=self.write)
        exit_button = Button(self.top, width=15, height=1, bd=8, command=self.exit_chat, text="Exit Chat",
                             font=('Segoe UI', '18'))

        self.user_box.grid(row=0, column=0)
        self.chat_box.grid(row=0, column=1, columnspan=2)
        self.send_input.grid(row=2, column=2, stick=W)
        send_button.grid(row=2, column=1, stick=W)
        exit_button.grid(row=2, column=0, stick=W)

        receive_thread = threading.Thread(target=self.recieve)
        receive_thread.start()

        self.top.mainloop()

    def main(self):
        instruction_label = Label(ROOT, text="Please enter your name and select a room")
        self.name_input = Entry(ROOT)
        self.r = StringVar()
        self.r.set("1")
        rb1 = Radiobutton(ROOT, text="Room 1", variable=self.r, value=1)
        rb2 = Radiobutton(ROOT, text="Room 2", variable=self.r, value=2)
        rb3 = Radiobutton(ROOT, text="Room 3", variable=self.r, value=3)
        rb4 = Radiobutton(ROOT, text="Room 4", variable=self.r, value=4)
        connect_button = Button(ROOT, text="connect to room", command=self.connect)

        instruction_label.grid(row=0, column=0)
        self.name_input.grid(row=1, column=0)

        rb1.grid(row=2, column=0)
        rb2.grid(row=3, column=0)
        rb3.grid(row=4, column=0)
        rb4.grid(row=5, column=0)

        connect_button.grid(row=6, column=0)

        ROOT.mainloop()


if __name__ == '__main__':
    Client = Client()
    Client.main()
