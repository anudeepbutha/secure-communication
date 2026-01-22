"""
Secure Communication Protocol - Client Implementation
Implements a stateful, symmetric-key-based secure client with:
- Pre-shared key authentication
- Session management
- Encrypted communication
- Replay attack protection

Message Flow:
1. CLIENT_HELLO (opcode 10) Client → Server
2. SERVER_CHALLENGE (opcode 20) Server → Client
3. CLIENT_DATA (opcode 30) Client → Server
4. SERVER_AGGR_RESPONSE (opcode 40) Server → Client

Error Handling:
- KEY_DESYNC_ERROR (opcode 50) - Key synchronization error
- TERMINATE (opcode 60) - Connection termination
"""

import socket
import struct
import logging
import threading
from typing import Optional

from crypto_utils import (
    generate_key, CryptoError, SecureMessage
)
from protocol_fsm import (
    ClientProtocol, ProtocolMessage, Opcode, MessageType,
    ProtocolState, StateTransitionError, KeyDesyncError
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecureClient')


class SecureClient:
    """
    Secure communication client using symmetric key cryptography.
    
    Features:
    - Pre-shared key authentication
    - Session-based communication
    - Encrypted message transfer with AES-GCM
    - Replay attack protection via nonces and timestamps
    - Message integrity via HMAC
    """
    
    def __init__(self, host: str = 'localhost', port: int = 9999,
                 pre_shared_key: bytes = None, client_id: int = 1):
        """
        Initialize the secure client.
        
        Args:
            host: Server host address
            port: Server port
            pre_shared_key: Pre-shared secret key (must match server's key)
            client_id: Client identifier (1-5)
        """
        if pre_shared_key is None:
            raise ValueError("Pre-shared key is required")
        
        if len(pre_shared_key) != 16:
            raise ValueError("Pre-shared key must be 16 bytes (128-bit)")
        
        if client_id < 1 or client_id > 5:
            raise ValueError("Client ID must be between 1 and 5")
        
        self.host = host
        self.port = port
        self.pre_shared_key = pre_shared_key
        self.client_id = client_id
        self.socket: Optional[socket.socket] = None
        self.protocol: Optional[ClientProtocol] = None
        self.connected = False
        self.session_id: Optional[bytes] = None
        self._lock = threading.Lock()
    
    def connect(self) -> bool:
        """
        Connect to the server and establish a secure session.
        
        Returns:
            True if connection and authentication successful
        """
        try:
            # Create socket and connect
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            logger.info(f"Connected to {self.host}:{self.port}")
            
            # Initialize protocol with client_id
            self.protocol = ClientProtocol(self.pre_shared_key, client_id=self.client_id)
            
            # Perform handshake
            if self._perform_handshake():
                self.connected = True
                self.session_id = self.protocol.session_id
                logger.info(f"Session established: {self.session_id.hex()[:16]}...")
                return True
            else:
                self.disconnect()
                return False
                
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.disconnect()
            return False
    
    def _perform_handshake(self) -> bool:
        """
        Perform the secure handshake protocol.
        
        Protocol Flow:
        1. Send CLIENT_HELLO (opcode 10)
        2. Receive SERVER_CHALLENGE (opcode 20)
        3. Send CLIENT_DATA (opcode 30)
        4. Receive SERVER_AGGR_RESPONSE (opcode 40)
        """
        try:
            # Step 1: Send CLIENT_HELLO (opcode 10)
            hello_msg = self.protocol.create_hello()
            self._send_message(hello_msg)
            logger.info(f"Sent CLIENT_HELLO (opcode {Opcode.CLIENT_HELLO.value})")
            
            # Step 2: Receive SERVER_CHALLENGE (opcode 20)
            server_challenge = self._recv_message()
            if not server_challenge:
                logger.error("No SERVER_CHALLENGE received")
                return False
            
            if server_challenge.msg_type == Opcode.KEY_DESYNC_ERROR:
                logger.error(f"KEY_DESYNC_ERROR: {server_challenge.payload.decode('utf-8', errors='replace')}")
                return False
            
            if server_challenge.msg_type != Opcode.SERVER_CHALLENGE:
                logger.error(f"Expected SERVER_CHALLENGE (opcode 20), got opcode {server_challenge.msg_type.value}")
                return False
            logger.info(f"Received SERVER_CHALLENGE (opcode {Opcode.SERVER_CHALLENGE.value})")
            
            # Step 3: Send CLIENT_DATA (opcode 30)
            client_data = self.protocol.process_server_challenge(server_challenge)
            self._send_message(client_data)
            logger.info(f"Sent CLIENT_DATA (opcode {Opcode.CLIENT_DATA.value})")
            
            # Step 4: Receive SERVER_AGGR_RESPONSE (opcode 40)
            server_response = self._recv_message()
            if not server_response:
                logger.error("No SERVER_AGGR_RESPONSE received")
                return False
            
            if server_response.msg_type == Opcode.KEY_DESYNC_ERROR:
                logger.error(f"KEY_DESYNC_ERROR (opcode 50): {server_response.payload.decode('utf-8', errors='replace')}")
                return False
            
            if server_response.msg_type != Opcode.SERVER_AGGR_RESPONSE:
                logger.error(f"Expected SERVER_AGGR_RESPONSE (opcode 40), got opcode {server_response.msg_type.value}")
                return False
            logger.info(f"Received SERVER_AGGR_RESPONSE (opcode {Opcode.SERVER_AGGR_RESPONSE.value})")
            
            # Process the response
            success = self.protocol.process_server_response(server_response)
            if success:
                logger.info("Authentication successful!")
            else:
                logger.error("Authentication failed!")
            
            return success
            
        except KeyDesyncError as e:
            logger.error(f"Key desync error during handshake: {e}")
            return False
        except StateTransitionError as e:
            logger.error(f"Protocol error during handshake: {e}")
            return False
        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            return False
    
    def _send_message(self, message: ProtocolMessage):
        """Send a protocol message"""
        data = message.to_bytes()
        length = struct.pack('>I', len(data))
        self.socket.sendall(length + data)
    
    def _recv_message(self) -> Optional[ProtocolMessage]:
        """Receive a protocol message"""
        try:
            length_data = self._recv_exact(4)
            if not length_data:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            data = self._recv_exact(length)
            if not data:
                return None
            
            return ProtocolMessage.from_bytes(data)
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            return None
    
    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def send(self, data: bytes) -> Optional[bytes]:
        """
        Send encrypted data to the server and receive response.
        
        Args:
            data: Data to send
        
        Returns:
            Server's response (decrypted) or None on error
        """
        if not self.connected:
            logger.error("Not connected")
            return None
        
        with self._lock:
            try:
                # Encrypt and send
                encrypted = self.protocol.create_data_message(data)
                length = struct.pack('>I', len(encrypted))
                self.socket.sendall(length + encrypted)
                logger.debug(f"Sent {len(data)} bytes (encrypted: {len(encrypted)})")
                
                # Receive response
                length_data = self._recv_exact(4)
                if not length_data:
                    logger.error("No response received")
                    return None
                
                length = struct.unpack('>I', length_data)[0]
                encrypted_response = self._recv_exact(length)
                if not encrypted_response:
                    return None
                
                # Decrypt response
                response = self.protocol.process_data_message(encrypted_response)
                logger.debug(f"Received {len(response)} bytes")
                return response
                
            except CryptoError as e:
                logger.error(f"Crypto error: {e}")
                return None
            except Exception as e:
                logger.error(f"Send error: {e}")
                return None
    
    def send_message(self, message: str) -> Optional[str]:
        """
        Send a text message and receive text response.
        
        Args:
            message: Text message to send
        
        Returns:
            Server's text response or None on error
        """
        response = self.send(message.encode('utf-8'))
        if response:
            return response.decode('utf-8', errors='replace')
        return None
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.connected:
            try:
                # Send close message
                self.send(b"__CLOSE__")
            except:
                pass
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.socket = None
        self.protocol = None
        self.connected = False
        self.session_id = None
        logger.info("Disconnected")
    
    def is_connected(self) -> bool:
        """Check if client is connected"""
        return self.connected
    
    def get_session_id(self) -> Optional[str]:
        """Get the current session ID as hex string"""
        if self.session_id:
            return self.session_id.hex()
        return None


class InteractiveClient:
    """Interactive command-line client for secure communication"""
    
    def __init__(self, client: SecureClient):
        self.client = client
    
    def run(self):
        """Run interactive session"""
        if not self.client.is_connected():
            if not self.client.connect():
                print("Failed to connect to server")
                return
        
        print("\n=== Secure Communication Session ===")
        print(f"Session ID: {self.client.get_session_id()[:16]}...")
        print("Type 'quit' to exit\n")
        
        while True:
            try:
                user_input = input("> ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() == 'quit' or user_input.lower() == 'exit':
                    print("Closing connection...")
                    break
                
                # Send message to server (numeric value)
                response = self.client.send_message(user_input)
                if response:
                    print(f"Server: {response}")
                else:
                    print("⚠️  Attack detected or connection closed!")
                    break
                    
            except KeyboardInterrupt:
                print("\nInterrupted")
                break
            except CryptoError as e:
                print(f"⚠️  Security Error: {e}")
                print("Connection terminated due to attack detection.")
                break
            except Exception as e:
                print(f"Error: {e}")
                break
        
        self.client.disconnect()
    
    def _print_status(self):
        """Print connection status"""
        print(f"Connected: {self.client.is_connected()}")
        print(f"Session ID: {self.client.get_session_id()}")
        print(f"Server: {self.client.host}:{self.client.port}")


def main():
    """Main function to run the client"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Communication Client')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=9999, help='Server port')
    parser.add_argument('--key', required=True, help='Pre-shared key (hex string)')
    parser.add_argument('--id', type=int, required=True, choices=[1,2,3,4,5],
                        help='Client ID (1-5)')
    parser.add_argument('--message', '-m', help='Send single message and exit')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Run in interactive mode')
    args = parser.parse_args()
    
    # Parse pre-shared key
    try:
        pre_shared_key = bytes.fromhex(args.key)
        if len(pre_shared_key) != 16:
            print("Error: Pre-shared key must be 16 bytes (32 hex characters)")
            return
    except ValueError:
        print("Error: Invalid hex string for pre-shared key")
        return
    
    # Create client
    client = SecureClient(
        host=args.host,
        port=args.port,
        pre_shared_key=pre_shared_key,
        client_id=args.id
    )
    
    try:
        if args.message:
            # Single message mode
            if client.connect():
                response = client.send_message(args.message)
                if response:
                    print(f"Response: {response}")
                client.disconnect()
        elif args.interactive:
            # Interactive mode
            interactive = InteractiveClient(client)
            interactive.run()
        else:
            # Default: interactive mode
            interactive = InteractiveClient(client)
            interactive.run()
            
    except KeyboardInterrupt:
        print("\nInterrupted")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
