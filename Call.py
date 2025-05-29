import socket
import threading
import pyaudio


class VoiceCall:
    def __init__(self, host, port, target_host, target_port):
        self.host = host
        self.port = port
        self.target_host = target_host
        self.target_port = target_port
        self.is_calling = False
        self.audio_stream_in = None
        self.audio_stream_out = None
        self.p_audio = pyaudio.PyAudio()
        self.CHUNK = 1024
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 44100
        self.send_socket = None
        self.receive_socket = None

    def start_call(self):
        """Starts the voice call, initializing audio streams and sockets."""
        self.is_calling = True
        try:
            # Setup sending socket
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Setup receiving socket
            self.receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.receive_socket.bind((self.host, self.port))

            # Setup audio input stream
            self.audio_stream_in = self.p_audio.open(format=self.FORMAT,
                                                     channels=self.CHANNELS,
                                                     rate=self.RATE,
                                                     input=True,
                                                     frames_per_buffer=self.CHUNK)

            # Setup audio output stream
            self.audio_stream_out = self.p_audio.open(format=self.FORMAT,
                                                      channels=self.CHANNELS,
                                                      rate=self.RATE,
                                                      output=True,
                                                      frames_per_buffer=self.CHUNK)

            # Start threads for sending and receiving audio
            threading.Thread(target=self._send_audio, daemon=True).start()
            threading.Thread(target=self._receive_audio, daemon=True).start()
            print(f"Voice call started with {self.target_host}:{self.target_port}")
            return True
        except Exception as e:
            print(f"Error starting call: {e}")
            self.stop_call()
            return False

    def _send_audio(self):
        """Captures audio from the microphone and sends it to the target peer."""
        while self.is_calling and self.audio_stream_in:
            try:
                data = self.audio_stream_in.read(self.CHUNK)
                if self.send_socket:
                    self.send_socket.sendto(data, (self.target_host, self.target_port))
            except Exception as e:
                print(f"Error sending audio: {e}")
                self.is_calling = False  # Stop if error occurs
                break

    def _receive_audio(self):
        """Receives audio data from the peer and plays it."""
        while self.is_calling and self.audio_stream_out:
            try:
                if self.receive_socket:
                    data, addr = self.receive_socket.recvfrom(self.CHUNK * self.CHANNELS * 2)  # Adjust buffer size
                    self.audio_stream_out.write(data)
            except socket.timeout:
                continue  # Expected if no data is being sent
            except Exception as e:
                print(f"Error receiving audio: {e}")
                self.is_calling = False  # Stop if error occurs
                break

    def stop_call(self):
        """Stops the voice call, closing streams and sockets."""
        self.is_calling = False
        print("Stopping voice call...")

        if self.audio_stream_in:
            self.audio_stream_in.stop_stream()
            self.audio_stream_in.close()
            self.audio_stream_in = None

        if self.audio_stream_out:
            self.audio_stream_out.stop_stream()
            self.audio_stream_out.close()
            self.audio_stream_out = None

        if self.send_socket:
            self.send_socket.close()
            self.send_socket = None

        if self.receive_socket:
            self.receive_socket.close()
            self.receive_socket = None

        # Terminate PyAudio instance only when completely done with audio
        # self.p_audio.terminate() # Consider if this should be here or in a __del__ method
        print("Voice call stopped.")