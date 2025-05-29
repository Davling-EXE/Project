"""Protocol for private messaging communication

This module implements a custom protocol for handling chat messages between clients and server.
The protocol uses a length-prefixed pipe-delimited format: <length>|<type>|<sender>|<recipient>|<content>|
The length field is zero-filled to 4 digits for consistent parsing.

Message Types:
- connect: Initial connection request from client
- disconnect: Client disconnection notification
- message: Private message between users
- group_message: Message sent to a group
- create_group: Request to create a new group
- join_group: Request to join an existing group
- user_list: Server broadcast of online users
- group_list: Server broadcast of user's groups
- error: Error message from server

Example Messages:
- Connection request: "0021|connect|alice|server||"
- Private message: "0031|message|alice|bob|Hello Bob!|"
- Group message: "0041|group_message|alice|general|Hello everyone!|"
- Create group: "0034|create_group|alice|server|general|"
- Join group: "0032|join_group|alice|server|general|"
- User list update: "0044|user_list|server|alice|bob,charlie,david|"
- Group list update: "0048|group_list|server|alice|general,work,friends|"
"""

LENGTH_FIELD_SIZE = 4  # Number of digits for the zero-filled length field

def create_msg(msg_type, sender, recipient, content):
    """
    Creates a message following the protocol format: <length>|<type>|<sender>|<recipient>|<content>|
    The length field is zero-filled to LENGTH_FIELD_SIZE digits for consistent parsing.

    Args:
        msg_type (str): Type of message - one of:
            - connect: Client connection request
            - disconnect: Client disconnection
            - message: Private message
            - group_message: Group message
            - create_group: Create group request
            - join_group: Join group request
            - user_list: Online users list
            - group_list: User's groups list
            - error: Error message
        sender (str): Username of message sender
        recipient (str): Username of intended recipient or group name
        content (str): Message payload

    Returns:
        str: Formatted protocol message with zero-filled length prefix
    """
    # Create the message body without length first, including terminating pipe
    message_body = f"{msg_type}|{sender}|{recipient}|{content}|"
    # Calculate the total length including the length field and separator pipe
    total_length = len(message_body) + LENGTH_FIELD_SIZE + 1  # length digits + 1 pipe
    # Zero-fill the length using the constant
    length_str = str(total_length).zfill(LENGTH_FIELD_SIZE)
    return f"{length_str}|{message_body}"

def parse_msg(my_socket):
    """
    Receive and parse a protocol message from a socket connection.

    This function handles receiving raw socket data and parsing it according
    to the protocol format: <length>|<type>|<sender>|<recipient>|<content>|
    The length field is zero-filled to LENGTH_FIELD_SIZE digits for consistent parsing.

    Args:
        my_socket (socket.socket): Connected socket to receive data from

    Returns:
        tuple: A 4-tuple containing:
            - msg_type (str): Message type (connect/disconnect/message/group_message/create_group/join_group/user_list/group_list/error)
            - sender (str): Username of message sender
            - recipient (str): Username of intended recipient or group name
            - content (str): Message content

    Error Handling:
        - Returns ('disconnect', '', '', '') if connection closed
        - Returns ('error', '', '', 'Invalid message format') if message malformed
    """
    try:
        # First, read the length prefix (LENGTH_FIELD_SIZE digits + 1 pipe)
        prefix_size = LENGTH_FIELD_SIZE + 1
        length_data = my_socket.recv(prefix_size).decode()
        if not length_data or len(length_data) != prefix_size:
            return 'disconnect', '', '', ''
        
        # Extract and validate the length
        if length_data[LENGTH_FIELD_SIZE] != '|':
            return 'error', '', '', 'Invalid length format'
        
        try:
            message_length = int(length_data[:LENGTH_FIELD_SIZE])
        except ValueError:
            return 'error', '', '', 'Invalid length value'
        
        # Read the remaining message based on the length
        remaining_length = message_length - prefix_size  # Subtract the bytes already read
        if remaining_length <= 0:
            return 'error', '', '', 'Invalid message length'
        
        message_data = my_socket.recv(remaining_length).decode()
        if len(message_data) != remaining_length:
            return 'error', '', '', 'Incomplete message received'
        
        # Parse the message: <type>|<sender>|<recipient>|<content>|
        parts = message_data.split('|', 4)
        if len(parts) != 5 or parts[4] != '':
            return 'error', '', '', 'Invalid message format'
        
        msg_type, sender, recipient, content, _ = parts
        return msg_type, sender, recipient, content
        
    except Exception as e:
        return 'error', '', '', f'Invalid message format: {str(e)}'