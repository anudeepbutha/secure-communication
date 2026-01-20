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
import json
import os
from typing import Dict, Optional, Callable, Any
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
    
    def __init__(self, host: str = 'localhost', port: int = 9999,
                 pre_shared_key: Optional[bytes] = None):
        """
        Initialize the secure server.
        
        Args:
            host: Server host address
            port: Server port
            pre_shared_key: Pre-shared secret key (will generate if not provided)
        """
        self.host = host
        self.port = port
        self.pre_shared_key = pre_shared_key or generate_key()
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.sessions: Dict[bytes, ClientSession] = {}
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.data_handler: Optional[Callable[[bytes, ClientSession], bytes]] = None
        self._lock = threading.Lock()
        
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
        logger.info(f"Pre-shared key: {self.pre_shared_key.hex()}")
        
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
        protocol = ServerProtocol(self.pre_shared_key)
        session: Optional[ClientSession] = None
        
        try:
            # Phase 1: Receive CLIENT_HELLO (opcode 10)
            hello_msg = self._recv_message(client_socket)
            if not hello_msg or hello_msg.msg_type != MessageType.CLIENT_HELLO:
                logger.error(f"Expected CLIENT_HELLO (opcode 10), got {hello_msg.msg_type if hello_msg else 'None'}")
                return
            
            logger.info(f"[{client_address}] Received CLIENT_HELLO (opcode {MessageType.CLIENT_HELLO.value})")
            
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
            client_socket.close()
            logger.info(f"[{client_address}] Connection closed")
    
    def _data_transfer_phase(self, sock: socket.socket, session: ClientSession):
        """Handle data transfer phase with attack detection"""
        protocol = session.protocol
        
        logger.info(f"[{session.client_address}] Entering DATA_TRANSFER phase")
        
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
                
                # Check for protocol messages vs data
                # Try to parse as protocol message first
                try:
                    # Decrypt the message
                    data = protocol.process_data_message(encrypted)
                    session.message_count += 1
                    session.last_activity = datetime.now()
                    
                    logger.info(f"[{session.client_address}] Received data: {len(data)} bytes")
                    
                    # Check for close command
                    if data == b"__CLOSE__":
                        logger.info(f"[{session.client_address}] Close requested")
                        # Send close acknowledgment
                        self._send_encrypted(sock, protocol, b"__CLOSE_ACK__")
                        break
                    
                    # Process data and send response
                    response = self._handle_data_message(data, session)
                    self._send_encrypted(sock, protocol, response)
                    
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


def create_echo_handler():
    """Create an echo handler that returns the received data"""
    def handler(data: bytes, session: ClientSession) -> bytes:
        logger.info(f"Echo handler: {data.decode('utf-8', errors='replace')}")
        return b"Echo: " + data
    return handler


def create_command_handler():
    """Create a command handler that processes commands"""
    def handler(data: bytes, session: ClientSession) -> bytes:
        try:
            command = data.decode('utf-8').strip()
            
            if command == "TIME":
                return f"Server time: {datetime.now().isoformat()}".encode()
            elif command == "SESSION":
                return f"Session ID: {session.session_id.hex()}".encode()
            elif command == "COUNT":
                return f"Messages: {session.message_count}".encode()
            elif command == "PING":
                return b"PONG"
            elif command.startswith("ECHO "):
                return command[5:].encode()
            else:
                return f"Unknown command: {command}".encode()
        except Exception as e:
            return f"Error processing command: {e}".encode()
    
    return handler


def main():
    """Main function to run the server"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Communication Server')
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=9999, help='Port number')
    parser.add_argument('--key', help='Pre-shared key (hex string)')
    parser.add_argument('--mode', choices=['echo', 'command'], default='echo',
                        help='Server mode: echo or command')
    args = parser.parse_args()
    
    # Parse pre-shared key if provided
    pre_shared_key = None
    if args.key:
        try:
            pre_shared_key = bytes.fromhex(args.key)
            if len(pre_shared_key) != 16:
                print("Error: Pre-shared key must be 16 bytes (32 hex characters)")
                return
        except ValueError:
            print("Error: Invalid hex string for pre-shared key")
            return
    
    # Create server
    server = SecureServer(
        host=args.host,
        port=args.port,
        pre_shared_key=pre_shared_key
    )
    
    # Set handler based on mode
    if args.mode == 'echo':
        server.set_data_handler(create_echo_handler())
        print("Server running in ECHO mode")
    else:
        server.set_data_handler(create_command_handler())
        print("Server running in COMMAND mode")
        print("Available commands: TIME, SESSION, COUNT, PING, ECHO <message>")
    
    print(f"\nPre-shared key (save this for clients):")
    print(f"  {server.pre_shared_key.hex()}")
    print()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    main()
