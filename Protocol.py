"""
author - nadav cohen
date   - 18/04/24
protocol for communication
"""

"""
constants
"""
MAX_PACKET = 1024


def create_msg(data, recipient, sender):
    """
    creates a message following the protocol
    :param data: message content
    :param recipient: recipient's username
    :param sender: sender's username
    :return: formatted message string
    """
    length_message = str(len(data))
    zfill_length_message = length_message.zfill(4)
    length_recipient = str(len(recipient))
    zfill_length_recipient = length_recipient.zfill(4)
    length_sender = str(len(sender))
    zfill_length_sender = length_sender.zfill(4)
    message = str(zfill_length_message) + data + str(zfill_length_recipient) + recipient + str(zfill_length_sender) + sender
    return message


def get_msg(my_socket):
    """
    Extract message from protocol
    :param my_socket: socket connection
    :return: tuple of (message, recipient, sender)
    """
    len_word = my_socket.recv(4).decode()
    if len_word.isnumeric():
        message = my_socket.recv(int(len_word)).decode()
        len_recipient = my_socket.recv(4).decode()
        if len_recipient.isnumeric():
            recipient = my_socket.recv(int(len_recipient)).decode()
            len_sender = my_socket.recv(4).decode()
            if len_sender.isnumeric():
                sender = my_socket.recv(int(len_sender)).decode()
                return message, recipient, sender
    return "Error", "server", "server"


def main():
    print("hello")


if __name__ == '__main__':
    main()
