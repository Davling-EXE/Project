"""
author - nadav cohen
date   - 18/04/24
protocol for communication
"""

"""
constants
"""
MAX_PACKET = 1024


def create_msg(data, room, name):
    """
    creates a message following the protocol
    :param data:
    :param room:
    :param name:
    :return:
    """
    length_message = str(len(data))
    zfill_length_message = length_message.zfill(4)
    length_name = str(len(name))
    zfill_length_name = length_name.zfill(4)
    message = str(zfill_length_message) + data + room + str(zfill_length_name) + name
    return message


def get_msg(my_socket):
    """
    Extract message from protocol, without message/name length
    :param my_socket:
    :return:
    """
    len_word = my_socket.recv(4).decode()
    if len_word.isnumeric():
        message = my_socket.recv(int(len_word)).decode()
        room = my_socket.recv(1).decode()
        len_name = my_socket.recv(4).decode()
        if len_name.isnumeric():
            username = my_socket.recv(int(len_name)).decode()
            return message, room, username
        else:
            return "Error", 0, "server"
    else:
        return "Error", 0, "server"


def main():
    print("hello")


if __name__ == '__main__':
    main()
