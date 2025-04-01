
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
ROOT.title("Chat Login")


class Client:

    def __init__(self):
        self.server = None
        self.user_box = None
        self.chat_box = None
        self.send_input = None
        self.top = None
        self.name_input = None
        self.selected_user = StringVar()
        self.username = ""

    def connect(self):
        """
        connects to the server
        :return:
        """
        try:
            self.username = self.name_input.get()
            if not self.username:
                messagebox.showerror("Error", "Please enter a username")
                return

            self.server = socket.socket()
            self.server.connect((SERVER_IP, PORT))
            self.server.send(create_msg("connect", self.username, "server", "").encode())

            msg_type, sender, recipient, content = parse_msg(self.server)
            if msg_type == "error":
                messagebox.showerror("Connection Error", content)
                self.server.close()
                return

            messagebox.showinfo("Connected successfully", f"Connected as {self.username}")
            self.open_chat()

        except socket.error as err:
            messagebox.showerror("Connection Error", str(err))

    def receive(self):
        """
        this takes care of receiving messages from the server
        :return:
        """
        while True:
            try:
                msg_type, sender, recipient, content = parse_msg(self.server)
                
                if msg_type == "error":
                    messagebox.showerror("Error", content)
                    self.top.destroy()
                    break
                elif msg_type == "user_list":
                    users = content.split(",")
                    self.user_box.delete(0, END)
                    for user in users:
                        if user != self.username:
                            self.user_box.insert(END, user)
                elif msg_type == "message":
                    self.chat_box.insert(END, f"{sender}: {content}\n")
                    self.chat_box.see(END)
                elif msg_type == "connect" and sender == "server":
                    self.chat_box.insert(END, f"Server: {content}\n")
                    self.chat_box.see(END)

            except socket.error as err:
                messagebox.showerror("Error", str(err))
                self.server.close()
                self.top.destroy()
                break

    def write(self):
        """
        sends message to server
        :return:
        """
        recipient = self.user_box.get(ACTIVE)
        message = self.send_input.get()
        if recipient and message:
            self.server.send(create_msg("message", self.username, recipient, message).encode())
            self.chat_box.insert(END, f"Me to {recipient}: {message}\n")
            self.chat_box.see(END)
            self.send_input.delete(0, END)
        else:
            messagebox.showwarning("Warning", "Please select a recipient and enter a message")

    def exit_chat(self):
        """
        leaves the chat
        :return:
        """
        self.server.send(create_msg("disconnect", self.username, "server", "").encode())
        self.top.destroy()

    def open_chat(self):
        """
        opens the chat gui
        :return:
        """
        self.top = Toplevel()
        self.top.title(f"Chat - {self.username}")

        # Left panel for user list
        left_frame = Frame(self.top)
        left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        Label(left_frame, text="Online Users", font=('Segoe UI', '12', 'bold')).pack(pady=5)
        self.user_box = Listbox(left_frame, width=20, height=25, bd=8)
        self.user_box.pack(fill=BOTH, expand=True)

        # Right panel for chat
        right_frame = Frame(self.top)
        right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.chat_box = ScrolledText(right_frame, width=80, height=25, state=NORMAL, bd=8)
        self.chat_box.pack(fill=BOTH, expand=True)

        # Bottom panel for input and buttons
        bottom_frame = Frame(self.top)
        bottom_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        self.send_input = Entry(bottom_frame, width=80, bd=8)
        self.send_input.pack(side=LEFT, expand=True, fill=X, padx=5)
        send_button = Button(bottom_frame, text="Send", font=('Segoe UI', '12'),
                          command=self.write, width=10)
        send_button.pack(side=LEFT, padx=5)
        exit_button = Button(bottom_frame, text="Exit Chat", font=('Segoe UI', '12'),
                          command=self.exit_chat, width=10)
        exit_button.pack(side=LEFT, padx=5)

        # Configure grid weights
        self.top.grid_columnconfigure(1, weight=1)
        self.top.grid_rowconfigure(0, weight=1)

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        self.top.mainloop()

    def main(self):
        # Create login window
        ROOT.geometry("300x150")
        frame = Frame(ROOT, padx=20, pady=20)
        frame.pack(expand=True, fill=BOTH)

        instruction_label = Label(frame, text="Enter your username to join the chat",
                               font=('Segoe UI', '12'))
        instruction_label.pack(pady=10)

        self.name_input = Entry(frame, font=('Segoe UI', '12'))
        self.name_input.pack(fill=X, pady=10)

        connect_button = Button(frame, text="Login", command=self.connect,
                             font=('Segoe UI', '12'), bg='#4CAF50', fg='white',
                             width=15, relief=RAISED)
        connect_button.pack(pady=10)

        ROOT.mainloop()


if __name__ == '__main__':
    Client = Client()
    Client.main()
