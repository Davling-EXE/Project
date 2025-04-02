"""Protocol for private messaging communication

This module implements a custom protocol for handling chat messages between clients and server.
The protocol uses a pipe-delimited format: <type>|<sender>|<recipient>|<content>

Message Types:
- connect: Initial connection request from client
- disconnect: Client disconnection notification
- message: Private message between users
- user_list: Server broadcast of online users
- error: Error message from server

Example Messages:
- Connection request: "connect|alice|server|" 
- Private message: "message|alice|bob|Hello Bob!"
- User list update: "user_list|server|alice|bob,charlie,david"
"""

def create_msg(msg_type, sender, recipient, content):
    """
    Creates a message following the protocol format: <type>|<sender>|<recipient>|<content>
    
    Args:
        msg_type (str): Type of message - one of:
            - connect: Client connection request
            - disconnect: Client disconnection
            - message: Private message
            - user_list: Online users list
            - error: Error message
        sender (str): Username of message sender
        recipient (str): Username of intended recipient
        content (str): Message payload
    
    Returns:
        str: Formatted protocol message
    """
    return f"{msg_type}|{sender}|{recipient}|{content}"

def parse_msg(my_socket):
    """
    Receive and parse a protocol message from a socket connection.
    
    This function handles receiving raw socket data and parsing it according
    to the protocol format. It includes error handling for disconnections and
    malformed messages.
    
    Args:
        my_socket (socket.socket): Connected socket to receive data from
        
    Returns:
        tuple: A 4-tuple containing:
            - msg_type (str): Message type (connect/disconnect/message/user_list/error)
            - sender (str): Username of message sender
            - recipient (str): Username of intended recipient
            - content (str): Message content
            
    Error Handling:
        - Returns ('disconnect', '', '', '') if connection closed
        - Returns ('error', '', '', 'Invalid message format') if message malformed
    """
    try:
        data = my_socket.recv(1024).decode()
        if not data:
            return 'disconnect', '', '', ''
        msg_type, sender, recipient, content = data.split('|')
        return msg_type, sender, recipient, content
    except:
        return 'error', '', '', 'Invalid message format'
