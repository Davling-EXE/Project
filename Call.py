import threading
import pyaudio
import time
from tkinter import *
from tkinter import messagebox
from Protocol import create_msg, parse_msg
import base64

"""
Voice Call Module

This module implements real-time voice calling functionality with encryption:
- Audio recording and playback using PyAudio
- Real-time audio streaming over TCP sockets
- AES encryption for secure voice transmission
- Call management (initiate, accept, decline, end calls)
- Audio quality configuration

Audio Configuration:
- Sample rate: 44100 Hz (CD quality)
- Channels: 1 (mono)
- Sample width: 2 bytes (16-bit)
- Chunk size: 1024 frames for low latency

Call Protocol:
- call_request: Initiate a call to another user
- call_accept: Accept an incoming call
- call_decline: Decline an incoming call
- call_end: End an active call
- voice_data: Encrypted audio data transmission
"""

# Audio configuration constants
CHUNK = 1024          # Audio chunk size for streaming
FORMAT = pyaudio.paInt16  # 16-bit audio format
CHANNELS = 1          # Mono audio
RATE = 44100          # Sample rate (44.1 kHz)
RECORD_SECONDS = 0.1  # Duration of each audio chunk


class VoiceCall:
    """Manages voice call functionality including audio recording, playback, and network transmission."""
    
    def __init__(self, client_instance):
        """
        Initialize voice call manager.
        
        Args:
            client_instance: Reference to main Client instance for network communication
        """
        self.client = client_instance
        self.audio = pyaudio.PyAudio()
        self.is_calling = False
        self.is_in_call = False
        self.call_partner = None
        self.recording_thread = None
        self.playback_thread = None
        self.audio_queue = []
        self.call_window = None
        
    def initiate_call(self, recipient):
        """
        Start a voice call with another user.
        
        Args:
            recipient (str): Username of the person to call
        """
        if self.is_calling or self.is_in_call:
            messagebox.showwarning("Call Error", "Already in a call or calling someone")
            return
            
        self.is_calling = True
        self.call_partner = recipient
        
        # Send call request to server
        call_msg = create_msg("call_request", self.client.username, recipient, "")
        self.client.server.send(call_msg.encode())
        
        # Show calling window
        self.show_calling_window(recipient)
        
    def accept_call(self, caller):
        """
        Accept an incoming voice call.
        
        Args:
            caller (str): Username of the person calling
        """
        self.is_in_call = True
        self.call_partner = caller
        
        # Send acceptance to server
        accept_msg = create_msg("call_accept", self.client.username, caller, "")
        self.client.server.send(accept_msg.encode())
        
        # Start call window and audio
        self.show_call_window(caller)
        self.start_audio()
        
    def decline_call(self, caller):
        """
        Decline an incoming voice call.
        
        Args:
            caller (str): Username of the person calling
        """
        decline_msg = create_msg("call_decline", self.client.username, caller, "")
        self.client.server.send(decline_msg.encode())
        
    def end_call(self):
        """
        End the current voice call.
        """
        if self.is_calling or self.is_in_call:
            # Send end call message
            end_msg = create_msg("call_end", self.client.username, self.call_partner, "")
            self.client.server.send(end_msg.encode())
            
        self.stop_audio()
        self.reset_call_state()
        
        if self.call_window:
            self.call_window.destroy()
            self.call_window = None
            
    def reset_call_state(self):
        """
        Reset all call-related state variables.
        """
        self.is_calling = False
        self.is_in_call = False
        self.call_partner = None
        self.audio_queue.clear()
        
    def start_audio(self):
        """
        Start audio recording and playback threads for the call.
        """
        if not self.is_in_call:
            return
            
        # Start recording thread
        self.recording_thread = threading.Thread(target=self.record_audio, daemon=True)
        self.recording_thread.start()
        
        # Start playback thread
        self.playback_thread = threading.Thread(target=self.play_audio, daemon=True)
        self.playback_thread.start()
        
    def stop_audio(self):
        """
        Stop audio recording and playback.
        """
        self.is_in_call = False
        
        # Threads will stop automatically when is_in_call becomes False
        
    def record_audio(self):
        """
        Record audio from microphone and send to call partner.
        Runs in a separate thread during calls.
        """
        try:
            stream = self.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK
            )
            
            while self.is_in_call:
                try:
                    # Record audio chunk
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    
                    # Send raw audio data through Client class for encryption
                    self.client.send_voice_data(self.call_partner, data)
                    
                    time.sleep(0.01)  # Small delay to prevent overwhelming the network
                    
                except Exception as e:
                    print(f"Recording error: {e}")
                    break
                    
            stream.stop_stream()
            stream.close()
            
        except Exception as e:
            print(f"Audio recording initialization error: {e}")
            
    def play_audio(self):
        """
        Play received audio data from call partner.
        Runs in a separate thread during calls.
        """
        try:
            stream = self.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                output=True,
                frames_per_buffer=CHUNK
            )
            
            while self.is_in_call:
                try:
                    if self.audio_queue:
                        audio_data = self.audio_queue.pop(0)
                        stream.write(audio_data)
                    else:
                        time.sleep(0.01)  # Wait for audio data
                        
                except Exception as e:
                    print(f"Playback error: {e}")
                    break
                    
            stream.stop_stream()
            stream.close()
            
        except Exception as e:
            print(f"Audio playback initialization error: {e}")
            
    def handle_voice_data(self, sender, voice_data):
        """
        Handle incoming voice data from call partner.
        
        Args:
            sender (str): Username of the sender
            voice_data (str): Base64 encoded encrypted audio data
        """
        if not self.is_in_call or sender != self.call_partner:
            return
            
        try:
            # Decode audio data (no decryption here - handled by Client class)
            audio_data = base64.b64decode(voice_data.encode())
                
            # Add to playback queue
            self.audio_queue.append(audio_data)
            
        except Exception as e:
            print(f"Voice data handling error: {e}")
            
    def show_calling_window(self, recipient):
        """
        Show window while calling someone.
        
        Args:
            recipient (str): Username being called
        """
        self.call_window = Toplevel()
        self.call_window.title(f"Calling {recipient}...")
        self.call_window.geometry(self.client.get_window_position(300, 150))
        self.call_window.resizable(False, False)
        
        Label(self.call_window, text=f"Calling {recipient}...", 
              font=('Segoe UI', 12)).pack(pady=20)
        
        Button(self.call_window, text="Cancel Call", 
               command=self.end_call, font=('Segoe UI', 10),
               bg='#f44336', fg='white').pack(pady=10)
               
        self.call_window.protocol("WM_DELETE_WINDOW", self.end_call)
        
    def show_call_window(self, partner):
        """
        Show window during an active call.
        
        Args:
            partner (str): Username of call partner
        """
        if self.call_window:
            self.call_window.destroy()
            
        self.call_window = Toplevel()
        self.call_window.title(f"Voice Call with {partner}")
        self.call_window.geometry(self.client.get_window_position(350, 200))
        self.call_window.resizable(False, False)
        
        Label(self.call_window, text=f"In call with {partner}", 
              font=('Segoe UI', 14, 'bold')).pack(pady=20)
              
        Label(self.call_window, text="🎤 Speaking...", 
              font=('Segoe UI', 12)).pack(pady=10)
        
        Button(self.call_window, text="End Call", 
               command=self.end_call, font=('Segoe UI', 12),
               bg='#f44336', fg='white', width=15).pack(pady=20)
               
        self.call_window.protocol("WM_DELETE_WINDOW", self.end_call)
        
    def show_incoming_call_dialog(self, caller):
        """
        Show dialog for incoming call.
        
        Args:
            caller (str): Username of the person calling
        """
        dialog = Toplevel()
        dialog.title("Incoming Call")
        dialog.geometry(self.client.get_window_position(300, 150))
        dialog.resizable(False, False)
        dialog.grab_set()  # Make dialog modal
        
        Label(dialog, text=f"{caller} is calling you", 
              font=('Segoe UI', 12, 'bold')).pack(pady=20)
        
        button_frame = Frame(dialog)
        button_frame.pack(pady=10)
        
        Button(button_frame, text="Accept", 
               command=lambda: [self.accept_call(caller), dialog.destroy()],
               font=('Segoe UI', 10), bg='#4CAF50', fg='white',
               width=10).pack(side=LEFT, padx=10)
               
        Button(button_frame, text="Decline", 
               command=lambda: [self.decline_call(caller), dialog.destroy()],
               font=('Segoe UI', 10), bg='#f44336', fg='white',
               width=10).pack(side=RIGHT, padx=10)
               
        dialog.protocol("WM_DELETE_WINDOW", lambda: [self.decline_call(caller), dialog.destroy()])
        
    def cleanup(self):
        """
        Clean up audio resources when shutting down.
        """
        self.stop_audio()
        if self.call_window:
            self.call_window.destroy()
        self.audio.terminate()