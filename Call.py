from typing import Any # Added for type hinting
import pyaudio
import socket
import threading
import time

# Audio settings
CHUNK = 1024  # Number of audio frames per buffer
FORMAT = pyaudio.paInt16  # Audio format (16-bit integers)
CHANNELS = 1  # Number of audio channels (1 for mono, 2 for stereo)
RATE = 44100  # Sampling rate (samples per second)


# --- Sending Thread ---
def send_audio(target_ip: str, target_port: int, stop_event: threading.Event, p_audio: pyaudio.PyAudio) -> None:
    """Captures audio from microphone and sends it over UDP."""
    print(f"Audio sender started. Target: {target_ip}:{target_port}")
    sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    stream_out = None
    try:
        stream_out = p_audio.open(format=FORMAT,
                                  channels=CHANNELS,
                                  rate=RATE,
                                  input=True,
                                  frames_per_buffer=CHUNK)
        print("Microphone stream opened for sending.")
        while not stop_event.is_set():
            try:
                data = stream_out.read(CHUNK, exception_on_overflow=False)
                sending_socket.sendto(data, (target_ip, target_port))
            except IOError as e:
                # This can happen if the read operation is too slow
                print(f"IOError in send_audio: {e}")
                time.sleep(0.01)  # Brief pause
            except Exception as e:
                print(f"Error in send loop: {e}")
                break
    except Exception as e:
        print(f"Could not open microphone stream or error in send_audio: {e}")
    finally:
        if stream_out:
            try:
                stream_out.stop_stream()
                stream_out.close()
            except Exception as e:
                print(f"Error closing output stream: {e}")
        sending_socket.close()
        print("Audio sender stopped.")


# --- Receiving Thread ---
def receive_audio(my_listen_ip: str, my_listen_port: int, stop_event: threading.Event, p_audio: pyaudio.PyAudio) -> None:
    """Receives audio over UDP and plays it on speakers."""
    print(f"Audio receiver started. Listening on: {my_listen_ip}:{my_listen_port}")
    receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        receiving_socket.bind((my_listen_ip, my_listen_port))
        receiving_socket.settimeout(1.0)  # Timeout to allow checking stop_event
    except Exception as e:
        print(f"Error binding receiver socket on {my_listen_ip}:{my_listen_port} - {e}")
        print("Please ensure the port is not in use and the IP is correct.")
        return

    stream_in = None
    try:
        stream_in = p_audio.open(format=FORMAT,
                                 channels=CHANNELS,
                                 rate=RATE,
                                 output=True,
                                 frames_per_buffer=CHUNK)
        print("Speaker stream opened for receiving.")
        while not stop_event.is_set():
            try:
                data, addr = receiving_socket.recvfrom(
                    CHUNK * CHANNELS * 2)  # Buffer size: CHUNK * channels * bytes_per_sample
                stream_in.write(data)
            except socket.timeout:
                continue  # Just to check stop_event periodically
            except Exception as e:
                print(f"Error receiving/playing audio: {e}")
                # For more serious errors, you might want to break
                # For minor ones (e.g., buffer issues), you might log and continue
                time.sleep(0.01)
    except Exception as e:
        print(f"Could not open speaker stream or error in receive_audio: {e}")
    finally:
        if stream_in:
            try:
                stream_in.stop_stream()
                stream_in.close()
            except Exception as e:
                print(f"Error closing input stream: {e}")
        receiving_socket.close()
        print("Audio receiver stopped.")


# --- Main ---
if __name__ == '__main__':
    p = pyaudio.PyAudio()  # Initialize PyAudio instance

    MY_LISTEN_IP = '0.0.0.0'  # Listen on all available network interfaces

    print("--- Voice Call Setup ---")
    try:
        MY_LISTEN_PORT = int(input("Enter YOUR listening port (e.g., 50000): "))
        TARGET_IP = input("Enter the OTHER person's IP address (e.g., 192.168.1.101 or 127.0.0.1 for local): ")
        TARGET_SEND_PORT = int(input(f"Enter the port {TARGET_IP} is listening on (e.g., 50001): "))
    except ValueError:
        print("Invalid port number. Please enter numeric values for ports.")
        p.terminate()
        exit()

    print(f"\n--- Configuration Summary ---")
    print(f"I will listen for audio on: {MY_LISTEN_IP}:{MY_LISTEN_PORT}")
    print(f"I will send my audio to:    {TARGET_IP}:{TARGET_SEND_PORT}")
    print("---------------------------\n")
    print("Initializing audio streams and network connections...")

    # Event to signal threads to stop
    stop_event = threading.Event()

    # Create and start threads
    # Pass the PyAudio instance 'p' to the threads
    sender_thread = threading.Thread(target=send_audio, args=(TARGET_IP, TARGET_SEND_PORT, stop_event, p))
    receiver_thread = threading.Thread(target=receive_audio, args=(MY_LISTEN_IP, MY_LISTEN_PORT, stop_event, p))

    print("Starting threads...")
    sender_thread.start()
    receiver_thread.start()

    try:
        input("Voice call active. Press Enter or type 'quit' to stop...\n")
    except KeyboardInterrupt:
        print("\nCtrl+C pressed. Exiting...")
    finally:
        print("Stopping threads and cleaning up...")
        stop_event.set()  # Signal threads to stop

        if sender_thread.is_alive():
            sender_thread.join(timeout=5)
        if receiver_thread.is_alive():
            receiver_thread.join(timeout=5)

        p.terminate()  # Terminate PyAudio instance
        print("Application closed.")
