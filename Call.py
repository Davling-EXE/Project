import socket
import threading
import pyaudio
from Protocol import create_msg, parse_msg # Assuming similar protocol usage for signaling
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
        self.stream = None
        self.is_active = False
        self.peer_udp_address = None # (ip, port) of the other user, relayed by server

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

        threading.Thread(target=self._send_audio, daemon=True).start()
        threading.Thread(target=self._receive_audio, daemon=True).start()
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
        self.is_active = False
        # Notify server and other client about call termination
        # Example: self.client_socket.send(create_msg("end_call", self.username, self.recipient_username, "").encode())
        if self.udp_socket:
            self.udp_socket.close()
        if self.audio:
            self.audio.terminate()
        print(f"Call between {self.username} and {self.recipient_username} ended.")

# Example usage (conceptual, will be integrated into Client.py)
if __name__ == '__main__':
    # This is just for testing the VoiceCall class in isolation
    # In the actual application, this would be managed by the Client class
    print("This module is not meant to be run directly. Import it into Client.py.")
    # Mock objects for testing
    class MockSocket:
        def send(self, data):
            print(f"Mock TCP send: {data}")
        def recv(self, size):
            return b""
        def close(self):
            print("Mock TCP socket closed")

    # Simulate two clients
    # Client A (Caller)
    mock_tcp_a = MockSocket()
    aes_key_ab = AESEncryption().key # Simulate shared key
    call_a = VoiceCall(mock_tcp_a, "Alice", "Bob", "127.0.0.1", 8821, True, aes_key_ab)

    # Client B (Receiver)
    mock_tcp_b = MockSocket()
    call_b = VoiceCall(mock_tcp_b, "Bob", "Alice", "127.0.0.1", 8821, False, aes_key_ab)

    # Simulate server relaying UDP info
    # Server would get call_a.udp_port and send to Bob
    # Server would get call_b.udp_port and send to Alice
    call_a.set_peer_udp_address("127.0.0.1", call_b.udp_port)
    call_b.set_peer_udp_address("127.0.0.1", call_a.udp_port)

    call_a.start_call()
    call_b.start_call()

    input("Press Enter to end call...\n")

    call_a.end_call()
    call_b.end_call()