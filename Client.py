
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
        self.top = None
        self.name_input = None
        self.username = ""
        self.chat_windows = {}
        self.main_window = None

    def get_window_position(self, width, height):
        """Calculate window position to center it on screen"""
        screen_width = ROOT.winfo_screenwidth()
        screen_height = ROOT.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        return f"{width}x{height}+{x}+{y}"

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
                    if sender not in self.chat_windows:
                        self.open_chat_window(sender)
                    self.chat_windows[sender].add_message(f"{sender}: {content}\n")
                elif msg_type == "connect" and sender == "server":
                    messagebox.showinfo("Server Message", content)

            except socket.error as err:
                messagebox.showerror("Error", str(err))
                self.server.close()
                self.top.destroy()
                break

    def write(self, recipient, message):
        """
        sends message to server
        :param recipient: recipient username
        :param message: message content
        :return:
        """
        if recipient and message:
            self.server.send(create_msg("message", self.username, recipient, message).encode())
            if recipient in self.chat_windows:
                self.chat_windows[recipient].add_message(f"Me: {message}\n")

    def exit_chat(self):
        """
        leaves the chat
        :return:
        """
        self.server.send(create_msg("disconnect", self.username, "server", "").encode())
        for window in self.chat_windows.values():
            window.window.destroy()
        self.main_window.destroy()

    class ChatWindow:
        def __init__(self, parent, username, recipient, write_callback):
            self.parent = parent
            self.window = Toplevel()
            self.window.title(f"Chat with {recipient}")
            self.window.geometry(parent.get_window_position(500, 600))
            self.window.minsize(400, 500)
            self.recipient = recipient
            self.write_callback = write_callback

            # Configure window close protocol
            self.window.protocol("WM_DELETE_WINDOW", self.exit_chat)

            # Top frame for buttons
            top_frame = Frame(self.window)
            top_frame.pack(fill=X, padx=15, pady=10)
            
            exit_button = Button(top_frame, text="Close Chat", font=('Segoe UI', '10'),
                                command=self.exit_chat)
            exit_button.pack(side=RIGHT)

            # Chat display area
            self.chat_box = ScrolledText(self.window, font=('Segoe UI', '10'), bd=2)
            self.chat_box.pack(fill=BOTH, expand=True, padx=15, pady=10)

            # Input area
            bottom_frame = Frame(self.window)
            bottom_frame.pack(fill=X, padx=15, pady=(0, 15))
            
            self.send_input = Entry(bottom_frame, font=('Segoe UI', '10'), bd=2)
            self.send_input.pack(side=LEFT, expand=True, fill=X, padx=(0, 10))
            self.send_input.bind('<Return>', self.send_message)
            
            send_button = Button(bottom_frame, text="Send", font=('Segoe UI', '10'),
                                command=self.send_message)
            send_button.pack(side=RIGHT)

        def send_message(self, event=None):
            message = self.send_input.get()
            if message:
                self.write_callback(self.recipient, message)
                self.send_input.delete(0, END)

        def add_message(self, message):
            self.chat_box.insert(END, message)
            self.chat_box.see(END)
            
        def exit_chat(self):
            """Closes the chat window and removes it from the parent's chat_windows dictionary"""
            if self.recipient in self.parent.chat_windows:
                del self.parent.chat_windows[self.recipient]
            self.window.destroy()

    def open_chat_window(self, recipient):
        if recipient not in self.chat_windows:
            self.chat_windows[recipient] = self.ChatWindow(self, self.username, recipient, self.write)

    def open_chat(self):
        """
        opens the main chat window with contacts list
        :return:
        """
        self.main_window = Toplevel()
        self.main_window.title(f"Contacts - {self.username}")
        self.main_window.geometry(self.get_window_position(350, 500))
        self.main_window.minsize(300, 400)

        # Configure window close protocol
        self.main_window.protocol("WM_DELETE_WINDOW", self.exit_chat)

        # Contacts list
        Label(self.main_window, text="Online Users", font=('Segoe UI', '12', 'bold')).pack(pady=10)
        self.user_box = Listbox(self.main_window, font=('Segoe UI', '10'), bd=2)
        self.user_box.pack(fill=BOTH, expand=True, padx=15, pady=(0, 10))
        self.user_box.bind('<Double-Button-1>', lambda e: self.open_chat_window(self.user_box.get(ACTIVE)))

        # Exit button
        exit_button = Button(self.main_window, text="Exit Chat", font=('Segoe UI', '11'),
                            command=self.exit_chat)
        exit_button.pack(pady=15)

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

    def main(self):
        # Create login window
        ROOT.geometry(self.get_window_position(300, 150))
        ROOT.minsize(250, 150)
        frame = Frame(ROOT, padx=20, pady=20)
        frame.pack(expand=True, fill=BOTH)

        instruction_label = Label(frame, text="Enter your username to join the chat",
                               font=('Segoe UI', '11'))
        instruction_label.pack(pady=10)

        self.name_input = Entry(frame, font=('Segoe UI', '11'))
        self.name_input.pack(fill=X, pady=10)

        connect_button = Button(frame, text="Login", command=self.connect,
                             font=('Segoe UI', '11'), bg='#4CAF50', fg='white',
                             width=12)
        connect_button.pack(pady=10)

        ROOT.mainloop()


if __name__ == '__main__':
    Client = Client()
    Client.main()
