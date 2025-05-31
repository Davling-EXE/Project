import socket
import threading
import pyaudio
from Encryption import AESEncryption # For encrypting voice data

# Audio settings
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100
CHUNK = 1024

class VoiceCall:
    def __init__(self, client_socket, username, recipient_username, server_ip, server_port, is_caller, aes_key):
        self.client_socket = client_socket # TCP socket for signaling with server
        self.username = username
        self.recipient_username = recipient_username
        self.server_ip = server_ip
        self.server_port = server_port # This might be a different port for UDP voice data
        self.is_caller = is_caller
        self.aes_key = aes_key # Shared AES key for this call
        self.aes_cipher = AESEncryption(key=self.aes_key)

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_port = 0 # Will be assigned by OS
        self.udp_socket.bind(("0.0.0.0", self.udp_port))
        self.udp_port = self.udp_socket.getsockname()[1]

        self.audio = pyaudio.PyAudio()
        self.stream = None # Input stream
        self.stream_out = None # Output stream
        self.is_active = False
        self.peer_udp_address = None # (ip, port) of the other user, relayed by server
        self.send_thread = None
        self.receive_thread = None

    def start_call(self):
        """Initiates the call or prepares to receive a call."""
        self.is_active = True
        # For caller: send call request to server
        # For receiver: server will notify, then this method is called
        # Both will then start sending/receiving UDP packets

        # Inform server about UDP port for relaying to peer
        # This message needs to be defined in Protocol.py and handled by Server.py
        # Example: "udp_info|username|recipient_username|udp_port"
        # self.client_socket.send(create_msg("udp_info", self.username, self.recipient_username, str(self.udp_port)).encode())

        self.send_thread = threading.Thread(target=self._send_audio, daemon=True)
        self.send_thread.start()
        self.receive_thread = threading.Thread(target=self._receive_audio, daemon=True)
        self.receive_thread.start()
        print(f"Voice call initiated between {self.username} and {self.recipient_username} on UDP port {self.udp_port}")

    def _send_audio(self):
        self.stream = self.audio.open(format=FORMAT, channels=CHANNELS,
                                      rate=RATE, input=True,
                                      frames_per_buffer=CHUNK)
        print("Microphone stream opened for sending.")
        while self.is_active:
            try:
                data = self.stream.read(CHUNK, exception_on_overflow=False)
                encrypted_data = self.aes_cipher.encrypt(data)
                if self.peer_udp_address: # Only send if peer address is known
                    self.udp_socket.sendto(encrypted_data, self.peer_udp_address)
            except Exception as e:
                print(f"Error sending audio: {e}")
                break
        if self.stream:
            self.stream.stop_stream()
            self.stream.close()
        print("Stopped sending audio.")

    def _receive_audio(self):
        self.stream_out = self.audio.open(format=FORMAT, channels=CHANNELS,
                                          rate=RATE, output=True,
                                          frames_per_buffer=CHUNK)
        print("Speaker stream opened for receiving.")
        while self.is_active:
            try:
                data, addr = self.udp_socket.recvfrom(CHUNK * 4) # Adjust buffer size as needed
                # Potentially verify addr if multiple peers could send, though server should manage this
                decrypted_data = self.aes_cipher.decrypt(data)
                self.stream_out.write(decrypted_data)
            except Exception as e:
                print(f"Error receiving audio: {e}")
                # If decryption fails or other errors, might need to handle gracefully
                # For now, just print and continue or break
                if isinstance(e, socket.timeout):
                    continue # Ignore timeouts if socket is non-blocking
                # break # Or break on other errors
        if self.stream_out:
            self.stream_out.stop_stream()
            self.stream_out.close()
        print("Stopped receiving audio.")

    def set_peer_udp_address(self, ip, port):
        self.peer_udp_address = (ip, int(port))
        print(f"Peer UDP address set to {self.peer_udp_address}")

    def end_call(self):
        print(f"Attempting to end call between {self.username} and {self.recipient_username}...")
        self.is_active = False # Signal threads to stop

        # Wait for threads to finish their cleanup
        if self.send_thread and self.send_thread.is_alive():
            print("Waiting for send_thread to join...")
            self.send_thread.join(timeout=2.0) # Wait for 2 seconds
            if self.send_thread.is_alive():
                print("Warning: send_thread did not join in time.")
        self.send_thread = None
        
        if self.receive_thread and self.receive_thread.is_alive():
            print("Waiting for receive_thread to join...")
            self.receive_thread.join(timeout=2.0) # Wait for 2 seconds
            if self.receive_thread.is_alive():
                print("Warning: receive_thread did not join in time.")
        self.receive_thread = None

        # Close UDP socket
        if self.udp_socket:
            try:
                self.udp_socket.close()
                print("UDP socket closed.")
            except Exception as e:
                print(f"Error closing UDP socket: {e}")
            self.udp_socket = None # Prevent further use

        # Terminate PyAudio
        if self.audio:
            try:
                self.audio.terminate()
                print("PyAudio terminated.")
            except Exception as e:
                print(f"Error terminating PyAudio: {e}")
            self.audio = None # Prevent further use
        
        # Nullify stream references as they are closed within threads
        self.stream = None
        self.stream_out = None

        print(f"Call between {self.username} and {self.recipient_username} ended procedures complete.")
