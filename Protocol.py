"""Protocol for private messaging communication"""

def create_msg(msg_type, sender, recipient, content):
    """
    Creates a message following the protocol format: <type>|<sender>|<recipient>|<content>
    :param msg_type: Message type (connect, disconnect, message, user_list)
    :param sender: Sender's username
    :param recipient: Recipient's username (or 'all' for broadcast)
    :param content: Message content
    :return: Formatted message string
    """
    return f"{msg_type}|{sender}|{recipient}|{content}"

def parse_msg(my_socket):
    """
    Extract message from protocol and parse its components
    :param my_socket: Socket to receive data from
    :return: Tuple of (message_type, sender, recipient, content)
    """
    try:
        data = my_socket.recv(1024).decode()
        if not data:
            return 'disconnect', '', '', ''
        msg_type, sender, recipient, content = data.split('|')
        return msg_type, sender, recipient, content
    except:
        return 'error', '', '', 'Invalid message format'
