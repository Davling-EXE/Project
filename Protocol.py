import json
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Message types
MSG_TYPE_CONNECT = "connect"
MSG_TYPE_DISCONNECT = "disconnect"
MSG_TYPE_CHAT = "chat"
MSG_TYPE_PRIVATE = "private"
MSG_TYPE_GROUP = "group"
MSG_TYPE_CREATE_GROUP = "create_group"
MSG_TYPE_JOIN_GROUP = "join_group"
MSG_TYPE_LEAVE_GROUP = "leave_group"
MSG_TYPE_USER_LIST = "user_list"
MSG_TYPE_GROUP_LIST = "group_list"
MSG_TYPE_LOGIN = "login"
MSG_TYPE_REGISTER = "register"
MSG_TYPE_ERROR = "error"
MSG_TYPE_SUCCESS = "success"
MSG_TYPE_KEY_EXCHANGE = "key_exchange"

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = base64.b64encode(pwdhash).decode('ascii')
    return salt.decode('ascii') + pwdhash

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64].encode('ascii')
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt, 
                                  100000)
    pwdhash = base64.b64encode(pwdhash).decode('ascii')
    return pwdhash == stored_password

def generate_key_pair():
    """Generate a new RSA key pair for encryption"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize keys for transmission
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def encrypt_message(message, public_key_pem):
    """Encrypt a message using the recipient's public key"""
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    # Generate a random AES key
    aes_key = os.urandom(32)  # 256-bit key
    
    # Encrypt the message with AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    
    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return the encrypted message, IV, and encrypted key
    return {
        "encrypted_message": base64.b64encode(encrypted_message).decode(),
        "iv": base64.b64encode(iv).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }

def decrypt_message(encrypted_data, private_key_pem):
    """Decrypt a message using the recipient's private key"""
    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    
    # Decode the base64 data
    encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
    iv = base64.b64decode(encrypted_data["iv"])
    encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
    
    # Decrypt the AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    return decrypted_message.decode()

def create_msg(msg_type, content, sender, recipient=None, group=None, encrypted_data=None):
    """
    Create a message in the protocol format
    
    Parameters:
    - msg_type: Type of message (connect, chat, etc.)
    - content: The actual message content
    - sender: Username of the sender
    - recipient: Username of the recipient (for private messages)
    - group: Group ID (for group messages)
    - encrypted_data: Dictionary containing encrypted message data
    
    Returns:
    - JSON string representing the message
    """
    message = {
        "type": msg_type,
        "sender": sender,
        "content": content,
    }
    
    if recipient:
        message["recipient"] = recipient
    
    if group:
        message["group"] = group
        
    if encrypted_data:
        message["encrypted"] = True
        message["encrypted_data"] = encrypted_data
    else:
        message["encrypted"] = False
    
    return json.dumps(message)

def parse_msg(message_json):
    """
    Parse a message from JSON format
    
    Parameters:
    - message_json: JSON string representing the message
    
    Returns:
    - Dictionary containing the parsed message
    """
    try:
        return json.loads(message_json)
    except json.JSONDecodeError:
        return None