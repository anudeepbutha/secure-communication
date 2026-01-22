"""
Interactive Man-in-the-Middle Attacker
Acts as a proxy between multiple clients and server, intercepting and modifying messages.

Supported Attacks:
1. Incorrect HMAC - Tampers with message content
2. Replay attacks - Replays captured encrypted messages
3. Message reordering - Reorders message sequence
4. Key desynchronization - Modifies messages to cause key desync

Usage:
    1. Start real server: python server.py --port 9999
    2. Start attacker: python attacks.py --client-port 8888 --server-port 9999
    3. Connect clients to attacker's port: python client.py --id 1 --key <key> --port 8888 -i
    4. Attacker shows connected clients and prompts for which client to attack
"""

import socket
import struct
import threading
import logging
import argparse
import time
from typing import Optional, Dict
from collections import deque
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MITMAttacker')


@dataclass
class ClientConnection:
    """Represents a connected client through the attacker proxy"""
    client_id: int
    client_socket: socket.socket
    server_socket: socket.socket
    client_address: tuple
    connected_at: datetime
    message_count: int = 0
    active: bool = True
    handshake_complete: bool = False  # Track if handshake is done


class MITMAttacker:
    """
    Man-in-the-Middle Attacker Proxy
    Sits between multiple clients and server, intercepting and modifying messages.
    Supports targeting specific clients for attacks.
    """
    
    ATTACK_TYPES = {
        '1': 'Incorrect HMAC',
        '2': 'Replay attacks',
        '3': 'Message reordering',
        '4': 'Key desynchronization'
    }
    
    def __init__(self, client_port: int, server_host: str, server_port: int):
        """
        Initialize MITM attacker.
        
        Args:
            client_port: Port to listen for client connections
            server_host: Real server host
            server_port: Real server port
        """
        self.client_port = client_port
        self.server_host = server_host
        self.server_port = server_port
        self.running = False
        
        # Track connected clients
        self.clients: Dict[int, ClientConnection] = {}  # client_id -> ClientConnection
        self.clients_lock = threading.Lock()
        
        # Attack configuration (set via interactive prompt)
        self.target_client_id: Optional[int] = None
        self.attack_type: Optional[str] = None
        self.attack_name: Optional[str] = None
        self.attack_performed: Dict[int, bool] = {}  # Track if attack performed per client
        
        # Storage for captured messages per client
        self.captured_messages: Dict[int, deque] = {}  # client_id -> deque of messages
        self.saved_session_messages: Dict[int, list] = {}  # client_id -> saved messages after session ends
        
        logger.info(f"MITM Attacker initialized")
        logger.info(f"Listening on port {client_port}, forwarding to {server_host}:{server_port}")
    
    def start(self):
        """Start the MITM proxy and interactive console"""
        self.running = True
        
        # Check if server is reachable
        print("\n" + "="*70)
        print(f"  MITM ATTACKER STARTUP")
        print("="*70)
        print(f"Checking if server is reachable at {self.server_host}:{self.server_port}...")
        
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            test_sock.connect((self.server_host, self.server_port))
            test_sock.close()
            print(f"✓ Server is reachable at {self.server_host}:{self.server_port}")
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            print(f"\n❌ ERROR: Cannot connect to server at {self.server_host}:{self.server_port}")
            print(f"   Please start the server first:")
            print(f"   python server.py --port {self.server_port} --mode command")
            print(f"\n   Error details: {e}\n")
            return
        
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('localhost', self.client_port))
        listener.listen(5)
        
        print("\n" + "="*70)
        print(f"  MITM ATTACKER ACTIVE")
        print("="*70)
        print(f"Listening for clients on port {self.client_port}...")
        print(f"Will forward to server at {self.server_host}:{self.server_port}")
        print("\nWaiting for client connections...")
        print("Once clients connect, you'll be prompted to select attack target.\n")
        
        # Start interactive console in separate thread
        console_thread = threading.Thread(target=self._interactive_console, daemon=True)
        console_thread.start()
        
        try:
            while self.running:
                try:
                    listener.settimeout(1.0)
                    client_sock, client_addr = listener.accept()
                    logger.info(f"Client connected from {client_addr}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
            
        except KeyboardInterrupt:
            print("\n\nShutting down attacker...")
        except Exception as e:
            logger.error(f"Fatal error: {e}")
        finally:
            listener.close()
            self._cleanup_all_clients()
    
    def _interactive_console(self):
        """Interactive console for selecting attack target and type"""
        time.sleep(1)  # Give time for initial setup
        
        while self.running:
            try:
                print("\n" + "="*70)
                print("  ATTACK CONSOLE")
                print("="*70)
                
                # Show connected clients
                with self.clients_lock:
                    if not self.clients:
                        print("No clients connected yet. Waiting...")
                        time.sleep(2)
                        continue
                    
                    print("\nConnected Clients:")
                    for client_id, conn in self.clients.items():
                        status = "ACTIVE" if conn.active else "DISCONNECTED"
                        print(f"  Client {client_id}: {conn.client_address} - {status} ({conn.message_count} messages)")
                
                print("\n" + "-"*70)
                print("Select attack target:")
                client_input = input("Enter Client ID to attack (or 'q' to quit, 'r' to refresh): ").strip()
                
                if client_input.lower() == 'q':
                    self.running = False
                    break
                elif client_input.lower() == 'r':
                    continue
                
                try:
                    target_id = int(client_input)
                    with self.clients_lock:
                        if target_id not in self.clients:
                            print(f"❌ Client {target_id} not connected!")
                            time.sleep(1)
                            continue
                        
                        if not self.clients[target_id].active:
                            print(f"❌ Client {target_id} is already disconnected!")
                            time.sleep(1)
                            continue
                    
                    # Select attack type
                    print("\nAvailable attacks:")
                    for key, name in self.ATTACK_TYPES.items():
                        print(f"  {key}. {name}")
                    
                    attack_input = input("\nSelect attack type (1-4): ").strip()
                    if attack_input not in self.ATTACK_TYPES:
                        print("❌ Invalid attack type!")
                        time.sleep(1)
                        continue
                    
                    # Set attack target
                    self.target_client_id = target_id
                    self.attack_type = attack_input
                    self.attack_name = self.ATTACK_TYPES[attack_input]
                    self.attack_performed[target_id] = False
                    
                    # Special handling for replay attack
                    if attack_input == '2':  # Replay attack
                        print(f"\n✓ Attack configured: Replay Attack")
                        print(f"  Target: Client {target_id}")
                        print(f"\nStrategy:")
                        print(f"  1. Capturing messages from Client {target_id}'s active session")
                        print(f"  2. Wait for client to disconnect (type 'quit' in client)")
                        print(f"  3. After disconnect, replay messages in NEW session")
                        print(f"\nℹ️  The client should send some messages then disconnect (type 'quit')")
                        
                        # Wait for client to disconnect
                        print(f"\nWaiting for Client {target_id} to disconnect...")
                        while self.running:
                            with self.clients_lock:
                                if target_id not in self.clients or not self.clients[target_id].active:
                                    break
                            time.sleep(0.5)
                        
                        # Now execute replay attack
                        time.sleep(1)  # Give time for cleanup
                        self._execute_replay_attack_after_session(target_id)
                        self.attack_performed[target_id] = True
                        
                    else:
                        # Normal attack handling (during active session)
                        print(f"\n✓ Attack configured:")
                        print(f"  Target: Client {target_id}")
                        print(f"  Attack: {self.attack_name}")
                        print(f"\nWaiting for Client {target_id} to send a message...")
                        
                        # Wait for attack to complete
                        while not self.attack_performed.get(target_id, False) and self.running:
                            time.sleep(0.5)
                        
                        if self.attack_performed.get(target_id, False):
                            print(f"\n✓ Attack executed on Client {target_id}!")
                            print(f"  Client {target_id} connection terminated.")
                    
                    # Reset for next attack
                    self.target_client_id = None
                    self.attack_type = None
                    self.attack_name = None
                    time.sleep(2)
                    
                except ValueError:
                    print("❌ Invalid input! Please enter a number.")
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Console error: {e}")
                time.sleep(1)
    
    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        """Handle a single client connection"""
        client_id = None
        server_sock = None
        
        try:
            # Connect to real server
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                server_sock.connect((self.server_host, self.server_port))
                logger.info(f"[{client_addr}] Connected to real server")
            except ConnectionRefusedError:
                print(f"\n❌ ERROR: Cannot connect to server at {self.server_host}:{self.server_port}")
                print(f"   Make sure the server is running:")
                print(f"   python server.py --port {self.server_port} --mode command\n")
                logger.error(f"[{client_addr}] Server not running at {self.server_host}:{self.server_port}")
                return
            
            # Intercept CLIENT_HELLO to extract client_id
            hello_msg = self._recv_message(client_sock)
            if not hello_msg or len(hello_msg) < 55:
                logger.error(f"[{client_addr}] Invalid CLIENT_HELLO")
                return
            
            # Extract client_id from CLIENT_HELLO payload (byte 50 of payload, after 4-byte length prefix)
            # Message structure: [length(4)][opcode(1)][seq(4)][timestamp(4)][payload_len(4)][payload]
            # Payload: client_random(32) + session_id(16) + version(2) + client_id(1)
            try:
                # Parse the protocol message structure
                payload_start = 17  # 1 + 4 + 4 + 4 + 4
                if len(hello_msg) >= payload_start + 51:
                    client_id = hello_msg[payload_start + 50]  # client_id at position 50 in payload
                else:
                    logger.error(f"[{client_addr}] CLIENT_HELLO too short")
                    return
            except Exception as e:
                logger.error(f"[{client_addr}] Error extracting client_id: {e}")
                return
            
            logger.info(f"[{client_addr}] Client ID: {client_id}")
            
            # Forward CLIENT_HELLO to server
            self._send_message(server_sock, hello_msg)
            
            # Register client
            conn = ClientConnection(
                client_id=client_id,
                client_socket=client_sock,
                server_socket=server_sock,
                client_address=client_addr,
                connected_at=datetime.now()
            )
            
            with self.clients_lock:
                self.clients[client_id] = conn
                self.captured_messages[client_id] = deque(maxlen=10)
            
            print(f"\n✓ Client {client_id} connected from {client_addr}")
            
            # Start bidirectional forwarding
            c2s_thread = threading.Thread(
                target=self._forward_client_to_server,
                args=(client_id,),
                daemon=True
            )
            s2c_thread = threading.Thread(
                target=self._forward_server_to_client,
                args=(client_id,),
                daemon=True
            )
            
            c2s_thread.start()
            s2c_thread.start()
            
            c2s_thread.join()
            s2c_thread.join()
            
        except Exception as e:
            logger.error(f"[{client_addr}] Error handling client: {e}")
        finally:
            if client_id:
                with self.clients_lock:
                    if client_id in self.clients:
                        self.clients[client_id].active = False
                        
                        # Save captured messages when session ends for replay attack
                        if client_id in self.captured_messages and len(self.captured_messages[client_id]) > 0:
                            self.saved_session_messages[client_id] = list(self.captured_messages[client_id])
                            print(f"\n✓ Saved {len(self.saved_session_messages[client_id])} messages from Client {client_id} for potential replay attack")
                
                print(f"\n✗ Client {client_id} disconnected")
            
            # Close both sockets to ensure client detects disconnection
            if client_sock:
                try:
                    client_sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    client_sock.close()
                except:
                    pass
            if server_sock:
                try:
                    server_sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    server_sock.close()
                except:
                    pass
    
    def _forward_client_to_server(self, client_id: int):
        """Forward messages from client to server with potential attacks"""
        with self.clients_lock:
            if client_id not in self.clients:
                return
            conn = self.clients[client_id]
        
        handshake_messages = 0  # Track handshake messages (CLIENT_HELLO, CLIENT_DATA)
        
        while self.running and conn.active:
            try:
                # Receive from client
                message = self._recv_message(conn.client_socket)
                if not message:
                    break
                
                conn.message_count += 1
                
                # Track handshake completion (CLIENT_HELLO at msg 1, CLIENT_DATA at msg 2)
                handshake_messages += 1
                if handshake_messages >= 2:
                    conn.handshake_complete = True
                
                # Check if this is the target and we're past handshake
                should_attack = (
                    self.target_client_id == client_id and
                    self.attack_type is not None and
                    not self.attack_performed.get(client_id, False) and
                    conn.handshake_complete  # Only attack after handshake
                )
                
                if should_attack:
                    print(f"\n[Attacker] Intercepting message from Client {client_id} (message #{conn.message_count})")
                    
                    # Special handling for replay attack (just capture)
                    if self.attack_type == '2':  # Replay attack
                        # Just capture and forward - actual attack happens after session
                        self.captured_messages[client_id].append((message[4:], "C→S"))  # Remove length prefix
                        print(f"  ✓ Message captured for replay attack (total: {len(self.captured_messages[client_id])})")
                        print(f"  ℹ️  Forwarding normally. Attack will execute after client disconnects.")
                        self._send_message(conn.server_socket, message)
                        continue
                    
                    # Special handling for reorder attack with multiple messages
                    elif self.attack_type == '3':  # Reorder attack
                        result = self._attack_reorder_with_send(message, client_id, conn.server_socket)
                        if result == "ATTACK_PERFORMED":
                            self.attack_performed[client_id] = True
                            print(f"\n⚠️  Attack performed on Client {client_id}. Terminating connection...")
                            conn.active = False
                            break
                        elif result == "CONTINUE":
                            continue  # Message already sent or held, continue loop
                    else:
                        # Perform attack normally
                        original_message = message
                        message = self._perform_attack(message, client_id, "C→S")
                        
                        # Send the (possibly modified) message
                        self._send_message(conn.server_socket, message)
                        
                        # Check if attack was actually performed (not just captured)
                        attack_actually_performed = (message != original_message) or (
                            self.attack_type in ['1', '4']  # HMAC and Key desync always perform immediately
                        )
                        
                        if attack_actually_performed:
                            self.attack_performed[client_id] = True
                            # Terminate this client after attack
                            print(f"\n⚠️  Attack performed on Client {client_id}. Terminating connection...")
                            conn.active = False
                            break
                        else:
                            # For replay/reorder, we captured but didn't attack yet
                            print(f"  ℹ Message captured. Waiting for next message to perform attack...")
                            continue
                else:
                    # Forward normally
                    self._send_message(conn.server_socket, message)
                    
            except Exception as e:
                logger.error(f"[Client {client_id}] Forward C→S error: {e}")
                break
    
    def _forward_server_to_client(self, client_id: int):
        """Forward messages from server to client"""
        with self.clients_lock:
            if client_id not in self.clients:
                return
            conn = self.clients[client_id]
        
        while self.running and conn.active:
            try:
                # Receive from server
                message = self._recv_message(conn.server_socket)
                if not message:
                    break
                
                # Forward to client
                self._send_message(conn.client_socket, message)
                
            except Exception as e:
                logger.error(f"[Client {client_id}] Forward S→C error: {e}")
                break
    
    def _recv_message(self, sock: socket.socket) -> Optional[bytes]:
        """Receive a length-prefixed message"""
        try:
            # Read 4-byte length prefix
            length_data = self._recv_exact(sock, 4)
            if not length_data:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            
            # Read message data
            data = self._recv_exact(sock, length)
            if not data:
                return None
            
            # Return with length prefix
            return length_data + data
        except Exception as e:
            return None
    
    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _send_message(self, sock: socket.socket, message: bytes):
        """Send a message (already has length prefix)"""
        sock.sendall(message)
    
    def _is_encrypted_data_message(self, data: bytes) -> bool:
        """Check if this looks like an encrypted data message (not handshake)"""
        if len(data) < 55:
            return False
        
        # Check if it's a protocol message (handshake) by parsing opcode
        try:
            # Skip length prefix (4 bytes), get opcode
            opcode = data[4]
            # Handshake opcodes are 10, 20, 30, 40
            if opcode in [10, 20, 30, 40]:
                return False
            return True
        except:
            return True
    
    def _perform_attack(self, message: bytes, client_id: int, direction: str) -> bytes:
        """
        Perform the selected attack on the message.
        
        Args:
            message: Original message with length prefix
            client_id: Target client ID
            direction: "C→S" or "S→C"
        
        Returns:
            Modified message (or original if no modification)
        """
        length_prefix = message[:4]
        data = message[4:]
        
        print(f"\n{'='*70}")
        print(f"⚡ PERFORMING ATTACK: {self.attack_name}")
        print(f"Target: Client {client_id}")
        print(f"Direction: {direction}")
        print(f"Message size: {len(data)} bytes")
        print(f"{'='*70}")
        
        if self.attack_type == '1':
            modified = self._attack_incorrect_hmac(data)
        elif self.attack_type == '2':
            modified = self._attack_replay(data, client_id, direction)
        elif self.attack_type == '3':
            modified = self._attack_reorder(data, client_id, direction)
        elif self.attack_type == '4':
            modified = self._attack_key_desync(data)
        else:
            modified = data
        
        if modified != data:
            print(f"✓ Message modified for attack")
            return length_prefix + modified
        
        return message
    
    def _attack_incorrect_hmac(self, data: bytes) -> bytes:
        """Attack: Flip bits in ciphertext to cause HMAC verification failure"""
        print("Attack strategy: Tamper with ciphertext to cause HMAC failure")
        
        if len(data) < 55:
            print("  ⚠ Message too short to attack")
            return data
        
        # Flip a bit in the ciphertext portion (after header, before HMAC)
        modified = bytearray(data)
        tamper_position = 30  # Middle of message
        original_byte = modified[tamper_position]
        modified[tamper_position] ^= 0x01  # Flip one bit
        
        print(f"  ✓ Tampered byte at position {tamper_position}: 0x{original_byte:02x} → 0x{modified[tamper_position]:02x}")
        print(f"  ✓ HMAC will fail on receiver side")
        
        return bytes(modified)
    
    def _attack_replay(self, data: bytes, client_id: int, direction: str) -> bytes:
        """Attack: Store message for later replay after session ends"""
        # Just capture the message - actual replay happens after session ends
        self.captured_messages[client_id].append((data, direction))
        
        print(f"Attack strategy: Capture messages for replay after session ends")
        print(f"  ✓ Message captured (total: {len(self.captured_messages[client_id])})")
        print(f"  ℹ Messages will be replayed in a NEW session after client disconnects")
        
        return data  # Forward normally during active session
    
    def _execute_replay_attack_after_session(self, client_id: int):
        """Execute replay attack after the original session has ended"""
        if client_id not in self.saved_session_messages or len(self.saved_session_messages[client_id]) == 0:
            print(f"\n❌ No saved messages for Client {client_id}")
            return
        
        print(f"\n{'='*70}")
        print(f"⚡ EXECUTING REPLAY ATTACK (Post-Session)")
        print(f"Target: Client {client_id}")
        print(f"Strategy: Create NEW session and replay OLD messages")
        print(f"{'='*70}")
        
        messages_to_replay = self.saved_session_messages[client_id]
        print(f"\n✓ Found {len(messages_to_replay)} captured messages from previous session")
        print(f"✓ Creating NEW connection to server...")
        
        try:
            # Create NEW connection to server
            replay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            replay_socket.connect((self.server_host, self.server_port))
            print(f"✓ Connected to server for replay attack")
            
            # Replay captured messages from old session
            print(f"\n⚡ REPLAYING OLD MESSAGES IN NEW SESSION:")
            for i, (msg_data, direction) in enumerate(messages_to_replay, 1):
                if direction != "C→S":
                    continue  # Only replay client→server messages
                
                print(f"\nReplaying message {i}/{len(messages_to_replay)}...")
                
                # Reconstruct full message with length prefix
                length_prefix = struct.pack('>I', len(msg_data))
                full_message = length_prefix + msg_data
                
                try:
                    # Send old message to server in new session
                    replay_socket.sendall(full_message)
                    print(f"  → Sent old message to server")
                    
                    # Try to receive response
                    replay_socket.settimeout(2.0)
                    try:
                        response_len_data = self._recv_exact(replay_socket, 4)
                        if response_len_data:
                            response_len = struct.unpack('>I', response_len_data)[0]
                            response_data = self._recv_exact(replay_socket, response_len)
                            if response_data:
                                print(f"  ← Received response ({len(response_data)} bytes)")
                                
                                # Check if it's an error message (opcode 50 or attack detected)
                                if len(response_data) >= 1:
                                    opcode = response_data[0]
                                    if opcode == 50:
                                        print(f"  ✓ Replay blocked: Server detected attack (opcode {opcode})")
                                    elif opcode in [60]:
                                        print(f"  ✓ Replay blocked: Session terminated (opcode {opcode})")
                        else:
                            print(f"  ✓ Replay blocked: Connection closed by server")
                            break
                    except socket.timeout:
                        print(f"  ✓ Replay blocked: No response (likely HMAC verification failed)")
                        break
                    
                except Exception as e:
                    print(f"  ✓ Replay blocked: {e}")
                    break
            
            replay_socket.close()
            print(f"\n{'='*70}")
            print(f"✓ REPLAY ATTACK COMPLETED")
            print(f"Result: Old messages replayed in NEW session")
            print(f"Expected: Server detected via HMAC failure (different session keys)")
            print(f"{'='*70}")
            
        except Exception as e:
            print(f"\n❌ Replay attack failed: {e}")
    
    def _attack_reorder(self, data: bytes, client_id: int, direction: str) -> bytes:
        """Attack: Reorder messages (legacy - use _attack_reorder_with_send instead)"""
        return data
    
    def _attack_reorder_with_send(self, data: bytes, client_id: int, server_socket: socket.socket) -> str:
        """
        Attack: Reorder messages - send msg1, HOLD msg2, send msg3, send msg2
        This demonstrates: msg1 → [hold msg2] → msg3 → msg2
        Returns: "ATTACK_PERFORMED", "CONTINUE", or "FORWARD_NORMAL"
        """
        # Store message with length prefix removed (data already has it removed in forwarding code)
        # We need to add it back for sending
        self.captured_messages[client_id].append((data, "C→S"))
        
        # Get messages from client→server direction
        same_dir_msgs = [msg for msg, d in self.captured_messages[client_id] if d == "C→S"]
        msg_count = len(same_dir_msgs)
        
        print(f"\n{'='*70}")
        print(f"⚡ REORDER ATTACK - Message {msg_count}/3")
        print(f"{'='*70}")
        
        # Step 1: Forward msg1 normally
        if msg_count == 1:
            print(f"Strategy: Reorder messages (msg1 → [hold msg2] → msg3 → msg2)")
            print(f"  → Step 1: Forwarding msg1 NORMALLY")
            print(f"     Server expects Round 1, receives Round 1 ✓")
            self._send_message(server_socket, data)
            return "CONTINUE"
        
        # Step 2: HOLD msg2 (do NOT send yet!)
        if msg_count == 2:
            print(f"  → Step 2: HOLDING msg2 (NOT sending to server)")
            print(f"     Message captured but not forwarded")
            print(f"     Waiting for msg3...")
            # Do NOT send to server - just return
            return "CONTINUE"
        
        # Step 3: On msg3, send msg3 FIRST (attack!), then send held msg2
        if msg_count >= 3:
            msg2 = same_dir_msgs[1]  # Held message (second)
            msg3 = data  # Current message (third)
            
            print(f"\n⚡ EXECUTING REORDER ATTACK:")
            print(f"  → Step 3a: Sending msg3 (Round 3) - but server expects Round 2!")
            print(f"     Server state: last_round=1, expects Round 2")
            print(f"     Sending: Round 3")
            print(f"     Result: Round number mismatch OR key mismatch")
            
            # Send msg3 first (this will cause the attack to be detected)
            self._send_message(server_socket, msg3)
            
            print(f"\n  → Step 3b: Now sending held msg2 (Round 2) - too late!")
            print(f"     Server already detected attack and terminated session")
            
            # Try to send msg2 (will likely fail as server closed connection)
            try:
                self._send_message(server_socket, msg2)
                print(f"     Sent msg2 (but connection likely already closed)")
            except Exception as e:
                print(f"     Cannot send msg2: {e}")
            
            print(f"\n✓ Reorder attack complete!")
            print(f"✓ Attack detection: Server received Round 3 when expecting Round 2")
            print(f"{'='*70}")
            
            return "ATTACK_PERFORMED"
        
        # Shouldn't reach here
        self._send_message(server_socket, data)
        return "CONTINUE"
    
    def _attack_key_desync(self, data: bytes) -> bytes:
        """Attack: Modify round number to cause key desynchronization"""
        print("Attack strategy: Modify round number to desynchronize keys")
        
        if len(data) < 23:
            print(f"  ⚠ Message too short ({len(data)} bytes)")
            return data
        
        # Parse and modify round number in header
        # Format: [Opcode(1)][Client_ID(1)][Round(4)][Direction(1)][IV(16)]
        modified = bytearray(data)
        
        # Extract current round number
        current_round = struct.unpack('>I', modified[2:6])[0]
        
        # Increment round number artificially
        fake_round = current_round + 10
        modified[2:6] = struct.pack('>I', fake_round)
        
        print(f"  ✓ Modified round number: {current_round} → {fake_round}")
        print(f"  ✓ This will cause key evolution desynchronization")
        print(f"  ✓ HMAC will fail because header was modified")
        
        return bytes(modified)
    
    def _cleanup_all_clients(self):
        """Close all client and server connections"""
        with self.clients_lock:
            for client_id, conn in self.clients.items():
                try:
                    conn.client_socket.close()
                except:
                    pass
                try:
                    conn.server_socket.close()
                except:
                    pass
            self.clients.clear()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Interactive Man-in-the-Middle Attacker for Secure Communication Protocol',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  1 - Incorrect HMAC: Tamper with message content
  2 - Replay attacks: Replay captured encrypted messages  
  3 - Message reordering: Send messages out of order
  4 - Key desynchronization: Modify round numbers to desync keys

Example Usage:
  # Start real server on port 9999
  python server.py --port 9999
  
  # Start attacker proxy on port 8888
  python attacks.py --client-port 8888 --server-port 9999
  
  # Connect clients to attacker's port (multiple clients supported)
  python client.py --id 1 --key c19b4d0dbb2550550314f0551d829e14 --port 8888 -i
  python client.py --id 2 --key fc1288ba000ab08d9bda2cd6eabd15ef --port 8888 -i
  
  # Attacker will show connected clients and prompt for attack target
        """
    )
    
    parser.add_argument('--client-port', type=int, default=8888,
                        help='Port for clients to connect to (default: 8888)')
    parser.add_argument('--server-host', default='localhost',
                        help='Real server host (default: localhost)')
    parser.add_argument('--server-port', type=int, default=9999,
                        help='Real server port (default: 9999)')
    
    args = parser.parse_args()
    
    # Display attacker info
    print("\n" + "="*70)
    print("  INTERACTIVE MAN-IN-THE-MIDDLE ATTACKER")
    print("="*70)
    print(f"Client port: {args.client_port}")
    print(f"Server: {args.server_host}:{args.server_port}")
    print("\nInstructions:")
    print(f"  1. Start the real server: python server.py --port {args.server_port}")
    print(f"  2. This attacker is listening on port {args.client_port}")
    print(f"  3. Connect clients: python client.py --id <ID> --key <key> --port {args.client_port} -i")
    print(f"  4. Attacker will show connected clients")
    print(f"  5. Select which client to attack and attack type")
    print(f"  6. Only the attacked client will be terminated")
    print("="*70 + "\n")
    
    # Create and start attacker
    attacker = MITMAttacker(
        client_port=args.client_port,
        server_host=args.server_host,
        server_port=args.server_port
    )
    
    try:
        attacker.start()
    except KeyboardInterrupt:
        print("\n\nAttacker stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")


if __name__ == "__main__":
    main()
