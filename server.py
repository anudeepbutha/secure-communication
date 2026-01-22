"""
Secure Communication Protocol - Server Implementation
Implements a stateful, symmetric-key-based secure server with:
- Pre-shared key authentication
- Session management
- Encrypted communication
- Replay attack protection
"""

import socket
import threading
import struct
import logging
from typing import Dict, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

from crypto_utils import (
    generate_key, generate_session_id, CryptoError,
    SecureMessage, get_timestamp
)
from protocol_fsm import (
    ServerProtocol, ProtocolMessage, MessageType,
    ProtocolState, StateTransitionError
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecureServer')


@dataclass
class ClientSession:
    """Represents an active client session"""
    session_id: bytes
    client_address: tuple
    protocol: ServerProtocol
    connected_at: datetime
    last_activity: datetime
    message_count: int = 0


class SecureServer:
    """
    Secure communication server using symmetric key cryptography.
    
    Features:
    - Pre-shared key authentication
    - Session-based communication
    - Encrypted message transfer with AES-GCM
    - Replay attack protection via nonces and timestamps
    - Message integrity via HMAC
    """
    
    def __init__(self, host: str = 'localhost', port: int = 9999):
        """
        Initialize the secure server.
        
        Args:
            host: Server host address
            port: Server port
        """
        self.host = host
        self.port = port
        
        # Hardcoded pre-shared keys for 5 clients (Client IDs 1-5)
        # In production, these would be securely distributed to clients
        self.client_keys = {
            1: bytes.fromhex('c19b4d0dbb2550550314f0551d829e14'),  # Client 1
            2: bytes.fromhex('fc1288ba000ab08d9bda2cd6eabd15ef'),  # Client 2
            3: bytes.fromhex('a3cc6de5b4d6b6798029f1bb5bbd1e10'),  # Client 3
            4: bytes.fromhex('d91baeccd0d6f5f423c8a4f81cf584a5'),  # Client 4
            5: bytes.fromhex('1b127762951e5537a14d7a164c166aa0'),  # Client 5
        }
        
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.sessions: Dict[bytes, ClientSession] = {}  # session_id -> ClientSession
        self.client_sessions: Dict[int, ClientSession] = {}  # client_id -> ClientSession
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.data_handler: Optional[Callable[[bytes, ClientSession], bytes]] = None
        self._lock = threading.Lock()
        
        # Per-round aggregation state
        self.round_aggregates: Dict[int, float] = {}  # round_number -> sum
        self.round_contributions: Dict[int, Dict[int, float]] = {}  # round_number -> {client_id -> value}
        self.round_client_count: Dict[int, int] = {}  # round_number -> count of clients
        self.aggregation_lock = threading.Lock()
        
        # Register default message handler
        self._setup_default_handlers()
    
    def _setup_default_handlers(self):
        """Setup default message handlers"""
        self.message_handlers[MessageType.CLIENT_DATA] = self._handle_data_message
    
    def set_data_handler(self, handler: Callable[[bytes, ClientSession], bytes]):
        """
        Set the handler for data messages.
        
        Args:
            handler: Function that takes (data, session) and returns response data
        """
        self.data_handler = handler
    
    def _handle_data_message(self, data: bytes, session: ClientSession) -> bytes:
        """Default data message handler"""
        if self.data_handler:
            return self.data_handler(data, session)
        return b"Message received"
    
    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        
        logger.info(f"Server started on {self.host}:{self.port}")

        while self.running:
            try:
                self.socket.settimeout(1.0)
                try:
                    client_socket, client_address = self.socket.accept()
                    logger.info(f"Connection from {client_address}")
                    
                    # Handle client in a new thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    logger.error(f"Server error: {e}")
                break
        
        self.socket.close()
        logger.info("Server stopped")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        logger.info("Stopping server...")
    
    def _send_message(self, sock: socket.socket, message: ProtocolMessage):
        """Send a protocol message over the socket"""
        data = message.to_bytes()
        # Send length prefix (4 bytes) followed by data
        length = struct.pack('>I', len(data))
        sock.sendall(length + data)
    
    def _recv_message(self, sock: socket.socket) -> Optional[ProtocolMessage]:
        """Receive a protocol message from the socket"""
        try:
            # Receive length prefix
            length_data = self._recv_exact(sock, 4)
            if not length_data:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            
            # Receive message data
            data = self._recv_exact(sock, length)
            if not data:
                return None
            
            return ProtocolMessage.from_bytes(data)
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            return None
    
    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes from socket"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _send_encrypted(self, sock: socket.socket, protocol: ServerProtocol, data: bytes):
        """Send encrypted data"""
        encrypted = protocol.create_data_message(data)
        # Send length prefix followed by encrypted data
        length = struct.pack('>I', len(encrypted))
        sock.sendall(length + encrypted)
    
    def _recv_encrypted(self, sock: socket.socket, protocol: ServerProtocol) -> Optional[bytes]:
        """Receive and decrypt data"""
        try:
            length_data = self._recv_exact(sock, 4)
            if not length_data:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            encrypted = self._recv_exact(sock, length)
            if not encrypted:
                return None
            
            return protocol.process_data_message(encrypted)
        except CryptoError as e:
            logger.error(f"Decryption error: {e}")
            raise
    
    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle a client connection"""
        session: Optional[ClientSession] = None
        client_id: Optional[int] = None
        
        try:
            # Phase 1: Receive CLIENT_HELLO (opcode 10)
            hello_msg = self._recv_message(client_socket)
            if not hello_msg or hello_msg.msg_type != MessageType.CLIENT_HELLO:
                logger.error(f"Expected CLIENT_HELLO (opcode 10), got {hello_msg.msg_type if hello_msg else 'None'}")
                return
            
            # Extract client_id from CLIENT_HELLO payload
            # Payload format: client_random (32) + session_id (16) + protocol_version (2) + client_id (1)
            if len(hello_msg.payload) < 51:
                logger.error(f"[{client_address}] CLIENT_HELLO payload too short")
                return
            
            client_id = hello_msg.payload[50]  # Client ID is at byte 50
            
            # Validate client_id
            if client_id not in self.client_keys:
                logger.error(f"[{client_address}] Invalid client_id {client_id} (must be 1-5)")
                return
            
            logger.info(f"[{client_address}] Received CLIENT_HELLO (opcode {MessageType.CLIENT_HELLO.value}) from Client {client_id}")
            
            # Initialize protocol with the client's pre-shared key
            pre_shared_key = self.client_keys[client_id]
            protocol = ServerProtocol(pre_shared_key, client_id=client_id)
            
            # Send SERVER_CHALLENGE (opcode 20)
            server_challenge = protocol.process_client_hello(hello_msg)
            self._send_message(client_socket, server_challenge)
            logger.info(f"[{client_address}] Sent SERVER_CHALLENGE (opcode {MessageType.SERVER_CHALLENGE.value})")
            
            # Phase 2: Receive CLIENT_DATA (opcode 30)
            client_data_msg = self._recv_message(client_socket)
            if not client_data_msg:
                logger.error("Expected CLIENT_DATA message")
                return
            
            if client_data_msg.msg_type == MessageType.KEY_DESYNC_ERROR:
                logger.error(f"[{client_address}] Received KEY_DESYNC_ERROR (opcode 50): {client_data_msg.payload.decode('utf-8', errors='replace')}")
                return
            
            if client_data_msg.msg_type != MessageType.CLIENT_DATA:
                logger.error(f"Expected CLIENT_DATA (opcode 30), got opcode {client_data_msg.msg_type.value}")
                return
            
            logger.info(f"[{client_address}] Received CLIENT_DATA (opcode {MessageType.CLIENT_DATA.value})")
            
            # Process CLIENT_DATA and send SERVER_AGGR_RESPONSE (opcode 40)
            server_response = protocol.process_client_data(client_data_msg)
            self._send_message(client_socket, server_response)
            
            if server_response.msg_type == MessageType.KEY_DESYNC_ERROR:
                logger.error(f"[{client_address}] Authentication failed - KEY_DESYNC_ERROR (opcode 50)")
                return
            
            logger.info(f"[{client_address}] Sent SERVER_AGGR_RESPONSE (opcode {MessageType.SERVER_AGGR_RESPONSE.value})")
            
            logger.info(f"[{client_address}] Authentication successful!")
            
            # Create session
            session = ClientSession(
                session_id=protocol.session_id,
                client_address=client_address,
                protocol=protocol,
                connected_at=datetime.now(),
                last_activity=datetime.now()
            )
            
            with self._lock:
                self.sessions[protocol.session_id] = session
                self.client_sessions[client_id] = session
            
            logger.info(f"[{client_address}] Session established for Client {client_id}")
            
            # Phase 4: Data transfer
            self._data_transfer_phase(client_socket, session)
            
        except StateTransitionError as e:
            logger.error(f"[{client_address}] Protocol error: {e}")
            # Send KEY_DESYNC_ERROR (opcode 50)
            try:
                error_msg = protocol.create_key_desync_error(str(e))
                self._send_message(client_socket, error_msg)
            except:
                pass
        except CryptoError as e:
            logger.error(f"[{client_address}] Crypto error: {e}")
            # Send KEY_DESYNC_ERROR (opcode 50)
            try:
                error_msg = protocol.create_key_desync_error(f"Crypto error: {e}")
                self._send_message(client_socket, error_msg)
            except:
                pass
        except Exception as e:
            logger.error(f"[{client_address}] Error: {e}")
        finally:
            # Cleanup
            if session and session.session_id in self.sessions:
                with self._lock:
                    del self.sessions[session.session_id]
                    if client_id and client_id in self.client_sessions:
                        del self.client_sessions[client_id]
                
                # Clear client's contributions from all rounds
                if client_id is not None:
                    with self.aggregation_lock:
                        for round_number in list(self.round_contributions.keys()):
                            if client_id in self.round_contributions[round_number]:
                                # Subtract client's contribution from round aggregate
                                value = self.round_contributions[round_number][client_id]
                                self.round_aggregates[round_number] -= value
                                
                                # Remove client from round contributions
                                del self.round_contributions[round_number][client_id]
                                
                                # Update client count
                                self.round_client_count[round_number] = len(self.round_contributions[round_number])
                                
                                logger.info(f"[Client {client_id}] Cleared contribution of {value} from Round {round_number}")
                                
                                # Remove empty rounds
                                if self.round_client_count[round_number] == 0:
                                    del self.round_aggregates[round_number]
                                    del self.round_contributions[round_number]
                                    del self.round_client_count[round_number]
                                    logger.info(f"[Round {round_number}] Cleared (no more clients)")
            
            client_socket.close()
            logger.info(f"[{client_address}] Connection closed" + (f" (Client {client_id})" if client_id else ""))
    
    def _data_transfer_phase(self, sock: socket.socket, session: ClientSession):
        """
        Handle data transfer phase with asynchronous response capability.
        
        The server listens continuously for incoming messages and delegates
        response handling to worker threads, allowing full-duplex communication.
        """
        protocol = session.protocol
        session_lock = threading.Lock()  # Per-session lock for thread-safe key evolution
        
        logger.info(f"[{session.client_address}] Entering DATA_TRANSFER phase (asynchronous mode)")
        
        def async_respond(data: bytes):
            """Worker thread to process and send response without blocking listener."""
            try:
                response = self._handle_data_message(data, session)
                with session_lock:
                    encrypted_resp = protocol.create_data_message(response)
                sock.sendall(struct.pack('>I', len(encrypted_resp)) + encrypted_resp)
                logger.debug(f"[{session.client_address}] Async response sent")
            except Exception as e:
                logger.error(f"[{session.client_address}] Async respond error: {e}")
        
        while self.running:
            try:
                sock.settimeout(30.0)  # 30 second timeout
                
                # Receive encrypted message
                length_data = self._recv_exact(sock, 4)
                if not length_data:
                    logger.info(f"[{session.client_address}] Client disconnected")
                    break
                
                length = struct.unpack('>I', length_data)[0]
                encrypted = self._recv_exact(sock, length)
                if not encrypted:
                    break
                
                # Decrypt and verify immediately (thread-safe)
                try:
                    with session_lock:
                        # Decrypt and verify round/HMAC immediately
                        # This detects replay, reordering, and tampering attacks
                        data = protocol.process_data_message(encrypted)
                    
                    session.message_count += 1
                    session.last_activity = datetime.now()
                    
                    logger.info(f"[{session.client_address}] Received data: {len(data)} bytes")
                    
                    # Check for close command
                    if data == b"__CLOSE__":
                        logger.info(f"[{session.client_address}] Close requested")
                        # Send close acknowledgment
                        with session_lock:
                            close_resp = protocol.create_data_message(b"__CLOSE_ACK__")
                        sock.sendall(struct.pack('>I', len(close_resp)) + close_resp)
                        break
                    
                    # Delegate response to a worker thread so listener stays active
                    threading.Thread(target=async_respond, args=(data,), daemon=True).start()
                    
                except CryptoError as e:
                    # ATTACK DETECTED: Could be replay, modification, tampering, or reordering
                    logger.error(f"[{session.client_address}] ⚠️  ATTACK DETECTED - {e}")
                    logger.error(f"[{session.client_address}] Attack types checked: Replay/Modification/Tampering/Reordering")
                    try:
                        # Send KEY_DESYNC_ERROR (opcode 50)
                        error_msg = protocol.create_key_desync_error(f"Attack detected: {e}")
                        self._send_message(sock, error_msg)
                    except:
                        pass
                    break
                    
            except socket.timeout:
                logger.debug(f"[{session.client_address}] Socket timeout")
                continue
            except Exception as e:
                logger.error(f"[{session.client_address}] Data transfer error: {e}")
                break
        
        # Send TERMINATE (opcode 60) on clean exit
        try:
            logger.info(f"[{session.client_address}] Sending TERMINATE (opcode {MessageType.TERMINATE.value})")
            terminate_msg = protocol.create_terminate("Session ended normally")
            self._send_message(sock, terminate_msg)
        except:
            pass
    
    def get_active_sessions(self) -> list:
        """Get list of active sessions"""
        with self._lock:
            return [
                {
                    'session_id': s.session_id.hex()[:16],
                    'client': f"{s.client_address[0]}:{s.client_address[1]}",
                    'connected_at': s.connected_at.isoformat(),
                    'message_count': s.message_count
                }
                for s in self.sessions.values()
            ]


def create_aggregation_handler(server: SecureServer):
    """
    Create an aggregation handler with PER-ROUND aggregation.
    
    Maintains separate aggregates for each round number across all clients.
    Round 1 from all clients aggregates together, Round 2 from all clients aggregates together, etc.
    """
    def handler(data: bytes, session: ClientSession) -> bytes:
        try:
            message = data.decode('utf-8').strip()
            client_id = session.protocol.client_id
            round_number = session.protocol.secure_message.round_number
            
            # Try to parse as numeric value
            try:
                value = float(message)
                
                with server.aggregation_lock:
                    # Initialize round if not exists
                    if round_number not in server.round_aggregates:
                        server.round_aggregates[round_number] = 0.0
                        server.round_contributions[round_number] = {}
                        server.round_client_count[round_number] = 0
                    
                    # Add to round aggregate
                    server.round_aggregates[round_number] += value
                    server.round_contributions[round_number][client_id] = value
                    server.round_client_count[round_number] = len(server.round_contributions[round_number])
                    
                    current_round_total = server.round_aggregates[round_number]
                    client_count = server.round_client_count[round_number]
                    
                    # Create breakdown string
                    contributions = server.round_contributions[round_number]
                    breakdown = ", ".join([f"C{cid}={val}" for cid, val in sorted(contributions.items())])
                
                logger.info(f"[Client {client_id}, Round {round_number}] Value: {value}, " +
                           f"Round Aggregate: {current_round_total} (from {client_count} clients)")
                logger.info(f"  Round {round_number} breakdown: {breakdown}")
                
                response = f"Round {round_number} Aggregate: {current_round_total:.2f} ({client_count} clients)".encode()
                return response
                
            except ValueError:
                # Not a number - return error
                return f"Invalid input. Please send numeric values only.".encode()
                
        except Exception as e:
            logger.error(f"Aggregation handler error: {e}")
            return f"Error: {e}".encode()
    
    return handler


def main():
    """Main function to run the server"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Communication Server')
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=9999, help='Port number')
    args = parser.parse_args()
    
    # Create server with hardcoded keys for 5 clients
    server = SecureServer(
        host=args.host,
        port=args.port
    )
    
    # Set aggregation handler (default mode)
    server.set_data_handler(create_aggregation_handler(server))
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    main()
