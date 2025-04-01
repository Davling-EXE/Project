
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
        self.name_input = None
        self.selected_user = None
        self.online_users = []

    def connect(self):
        """
        connects to the server
        :return:
        """
        try:
            self.server = socket.socket()
            self.server.connect((SERVER_IP, PORT))

            self.server.send(create_msg("connect", "server", self.name_input.get()).encode())

            messagebox.showinfo("Connected successfully", "Connected as " + self.name_input.get())

            self.open_chat()

        except socket.error as err:
            messagebox.showerror("an error occurred while trying to connect to the server", err)

    def receive(self):
        """
        this takes care of receiving messages from the server
        :return:
        """
        while True:
            try:
                message, recipient, sender = get_msg(self.server)
                if message == "issue connecting" and recipient == "server" and sender == "server":
                    self.top.destroy()
                elif message.startswith("online_users:") and sender == "server":
                    self.online_users = message[12:].split(", ")
                    self.user_box.delete(0, END)
                    for user in self.online_users:
                        if user != self.name_input.get():
                            self.user_box.insert(END, user)
                else:
                    self.chat_box.insert(END, f"{sender} : {message}\n")
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
        if self.selected_user:
            self.server.send(create_msg(self.send_input.get(), self.selected_user, self.name_input.get()).encode())
            self.send_input.delete(0, END)
        else:
            messagebox.showwarning("No recipient selected", "Please select a user to send message to")

    def exit_chat(self):
        """
        leaves the chat
        :return:
        """
        self.server.send(create_msg("disconnect", "server", self.name_input.get()).encode())
        self.top.destroy()

    def select_user(self, event):
        """
        handles user selection from the list
        :param event: event object
        :return: None
        """
        selection = self.user_box.curselection()
        if selection:
            self.selected_user = self.user_box.get(selection[0])
            self.top.title(f"Chat with {self.selected_user}")

    def open_chat(self):
        """
        opens the chat gui
        :return:
        """
        self.top = Toplevel()

        self.top.title(f"Chat - {self.name_input.get()}")
        user_list_label = Label(self.top, text="Online Users", font=('Segoe UI', '12', 'bold'))
        self.user_box = Listbox(self.top, width=20, height=25, bd=8)
        self.user_box.bind('<<ListboxSelect>>', self.select_user)
        self.chat_box = ScrolledText(self.top, width=80, height=25, state=NORMAL, bd=8)
        self.send_input = Entry(self.top, width=80, bd=8)
        send_button = Button(self.top, width=10, height=1, bd=8, text="Send", font=('Segoe UI', '18'),
                             command=self.write)
        exit_button = Button(self.top, width=15, height=1, bd=8, command=self.exit_chat, text="Exit Chat",
                             font=('Segoe UI', '18'))

        user_list_label.grid(row=0, column=0)
        self.user_box.grid(row=1, column=0)
        self.chat_box.grid(row=0, column=1, rowspan=2, columnspan=2)
        self.send_input.grid(row=2, column=2, stick=W)
        send_button.grid(row=2, column=1, stick=W)
        exit_button.grid(row=2, column=0, stick=W)

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        self.top.mainloop()

    def main(self):
        instruction_label = Label(ROOT, text="Please enter your name to join the chat", font=('Segoe UI', '12'))
        self.name_input = Entry(ROOT, width=30)
        connect_button = Button(ROOT, text="Connect", command=self.connect, width=20)

        instruction_label.grid(row=0, column=0, pady=10)
        self.name_input.grid(row=1, column=0, pady=5)
        connect_button.grid(row=2, column=0, pady=10)

        ROOT.mainloop()


if __name__ == '__main__':
    Client = Client()
    Client.main()
