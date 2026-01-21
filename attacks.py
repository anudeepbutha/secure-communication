"""
Interactive Man-in-the-Middle Attacker
Acts as a proxy between client and server, intercepting and modifying messages.

Supported Attacks:
1. Incorrect HMAC - Tampers with message content
2. Replay attacks - Replays captured encrypted messages
3. Message reordering - Reorders message sequence
4. Key desynchronization - Modifies messages to cause key desync

Usage:
    1. Start real server: python server.py --port 9999 --key <hex_key>
    2. Start attacker: python attacks.py --attack 1 --client-port 8888 --server-port 9999
    3. Connect client to attacker's port: python client.py --port 8888 --key <hex_key> -i
    4. Send messages - attacker will intercept and modify them
"""

import socket
import struct
import time
import threading
import logging
import os
import sys
import argparse
from typing import Optional, Tuple, Dict
from collections import deque

from crypto_utils import (
    generate_key, CryptoError, SecureMessage,
    NonceManager, derive_directional_keys
)
from protocol_fsm import (
    ClientProtocol, ServerProtocol, ProtocolMessage, MessageType,
    ProtocolState
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MITMAttacker')


class MITMAttacker:
    """
    Man-in-the-Middle Attacker Proxy
    Sits between client and server, intercepting and modifying messages.
    """
    
    ATTACK_TYPES = {
        '1': 'Incorrect HMAC',
        '2': 'Replay attacks',
        '3': 'Message reordering',
        '4': 'Key desynchronization'
    }
    
    def __init__(self, client_port: int, server_host: str, server_port: int, attack_type: str):
        """
        Initialize MITM attacker.
        
        Args:
            client_port: Port to listen for client connections
            server_host: Real server host
            server_port: Real server port
            attack_type: Type of attack to perform (1-4)
        """
        self.client_port = client_port
        self.server_host = server_host
        self.server_port = server_port
        self.attack_type = attack_type
        self.attack_name = self.ATTACK_TYPES.get(attack_type, "Unknown")
        self.running = False
        
        # Storage for captured messages
        self.captured_messages: deque = deque(maxlen=10)
        self.message_count = 0
        self.attack_performed = False
        
        logger.info(f"MITM Attacker initialized")
        logger.info(f"Attack type: {self.attack_name}")
        logger.info(f"Listening on port {client_port}, forwarding to {server_host}:{server_port}")
    
    def start(self):
        """Start the MITM proxy"""
        self.running = True
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('localhost', self.client_port))
        listener.listen(1)
        
        print("\n" + "="*70)
        print(f"  MITM ATTACKER ACTIVE - Attack Type: {self.attack_name}")
        print("="*70)
        print(f"Listening for client on port {self.client_port}...")
        print(f"Will forward to server at {self.server_host}:{self.server_port}")
        print("Waiting for client connection...\n")
        
        try:
            client_socket, client_addr = listener.accept()
            logger.info(f"Client connected from {client_addr}")
            print(f"✓ Client connected from {client_addr}")
            
            # Connect to real server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            logger.info(f"Connected to real server at {self.server_host}:{self.server_port}")
            print(f"✓ Connected to server at {self.server_host}:{self.server_port}\n")
            
            # Start forwarding threads
            client_to_server = threading.Thread(
                target=self._forward_client_to_server,
                args=(client_socket, server_socket),
                daemon=True
            )
            server_to_client = threading.Thread(
                target=self._forward_server_to_client,
                args=(server_socket, client_socket),
                daemon=True
            )
            
            client_to_server.start()
            server_to_client.start()
            
            # Wait for threads to complete
            client_to_server.join()
            server_to_client.join()
            
        except KeyboardInterrupt:
            print("\n\nAttacker interrupted by user")
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            listener.close()
            self.running = False
            print("\nMITM Attacker stopped")
    
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
            
            return length_data + data  # Return with length prefix
        except Exception as e:
            logger.debug(f"Error receiving message: {e}")
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
    
    def _forward_client_to_server(self, client_sock: socket.socket, server_sock: socket.socket):
        """Forward messages from client to server with potential attacks"""
        print("="*70)
        print("FORWARDING: Client → Server (with attack capability)")
        print("="*70 + "\n")
        
        while self.running:
            try:
                message = self._recv_message(client_sock)
                if not message:
                    logger.info("Client disconnected")
                    break
                
                self.message_count += 1
                length = struct.unpack('>I', message[:4])[0]
                data = message[4:]
                
                logger.info(f"[C→S] Message #{self.message_count}: {length} bytes")
                
                # Check if this is an encrypted data message (after handshake)
                if self._is_encrypted_data_message(data) and not self.attack_performed:
                    print("\n" + "🎯"*35)
                    print(f"ENCRYPTED DATA MESSAGE INTERCEPTED! (Message #{self.message_count})")
                    print("🎯"*35)
                    
                    # Perform attack
                    modified_message = self._perform_attack(message, "C→S")
                    
                    if modified_message != message:
                        self.attack_performed = True
                        print(f"\n⚠️  ATTACK EXECUTED: {self.attack_name}")
                        print("⚠️  Modified message sent to server")
                        print("⚠️  Server should detect tampering and terminate connection\n")
                        self._send_message(server_sock, modified_message)
                    else:
                        self._send_message(server_sock, message)
                else:
                    # Forward handshake messages normally
                    self._send_message(server_sock, message)
                    logger.debug(f"[C→S] Forwarded normally")
                
            except Exception as e:
                logger.error(f"Error in client→server forwarding: {e}")
                break
        
        self._cleanup_sockets(client_sock, server_sock)
    
    def _forward_server_to_client(self, server_sock: socket.socket, client_sock: socket.socket):
        """Forward messages from server to client with potential attacks"""
        print("="*70)
        print("FORWARDING: Server → Client (with attack capability)")
        print("="*70 + "\n")
        
        while self.running:
            try:
                message = self._recv_message(server_sock)
                if not message:
                    logger.info("Server disconnected")
                    break
                
                length = struct.unpack('>I', message[:4])[0]
                data = message[4:]
                
                logger.info(f"[S→C] Response: {length} bytes")
                
                # Check if this is an encrypted data message
                if self._is_encrypted_data_message(data) and not self.attack_performed:
                    print("\n" + "🎯"*35)
                    print(f"ENCRYPTED RESPONSE INTERCEPTED!")
                    print("🎯"*35)
                    
                    # Perform attack on server responses too
                    modified_message = self._perform_attack(message, "S→C")
                    
                    if modified_message != message:
                        self.attack_performed = True
                        print(f"\n⚠️  ATTACK EXECUTED: {self.attack_name}")
                        print("⚠️  Modified message sent to client")
                        print("⚠️  Client should detect tampering and terminate connection\n")
                        self._send_message(client_sock, modified_message)
                    else:
                        self._send_message(client_sock, message)
                else:
                    # Forward normally
                    self._send_message(client_sock, message)
                    logger.debug(f"[S→C] Forwarded normally")
                
            except Exception as e:
                logger.error(f"Error in server→client forwarding: {e}")
                break
        
        self._cleanup_sockets(server_sock, client_sock)
    
    def _is_encrypted_data_message(self, data: bytes) -> bool:
        """Check if this looks like an encrypted data message (not handshake)"""
        # Encrypted data messages are longer and don't start with handshake opcodes
        if len(data) < 55:  # Minimum: header(23) + one block(16) + hmac(32) = 71
            return False
        
        # Check if it's a protocol message (handshake)
        try:
            opcode = struct.unpack('>B', data[0:1])[0]
            # Handshake opcodes: 10, 20, 30, 40, 50, 60
            if opcode in [10, 20, 30, 40, 50, 60]:
                return False
            # If opcode is unusual, it might be encrypted data
            return True
        except:
            return True
    
    def _perform_attack(self, message: bytes, direction: str) -> bytes:
        """
        Perform the selected attack on the message.
        
        Args:
            message: Original message with length prefix
            direction: "C→S" or "S→C"
        
        Returns:
            Modified message (or original if no modification)
        """
        length_prefix = message[:4]
        data = message[4:]
        
        print(f"\n{'='*70}")
        print(f"PERFORMING ATTACK: {self.attack_name}")
        print(f"Direction: {direction}")
        print(f"Message size: {len(data)} bytes")
        print(f"{'='*70}")
        
        if self.attack_type == '1':  # Incorrect HMAC
            modified = self._attack_incorrect_hmac(data)
        elif self.attack_type == '2':  # Replay attack
            modified = self._attack_replay(data, direction)
        elif self.attack_type == '3':  # Message reordering
            modified = self._attack_reorder(data, direction)
        elif self.attack_type == '4':  # Key desynchronization
            modified = self._attack_key_desync(data)
        else:
            modified = data
        
        if modified != data:
            # Update length prefix if size changed
            new_length = struct.pack('>I', len(modified))
            return new_length + modified
        
        return message
    
    def _attack_incorrect_hmac(self, data: bytes) -> bytes:
        """Attack: Flip bits in ciphertext to cause HMAC verification failure"""
        print("Attack strategy: Tamper with ciphertext to cause HMAC failure")
        
        if len(data) < 55:
            print("  Message too short to tamper")
            return data
        
        # Flip a bit in the ciphertext portion (after header, before HMAC)
        modified = bytearray(data)
        tamper_position = 30  # Middle of message
        original_byte = modified[tamper_position]
        modified[tamper_position] ^= 0x01  # Flip one bit
        
        print(f"  ✓ Tampered byte at position {tamper_position}: 0x{original_byte:02x} → 0x{modified[tamper_position]:02x}")
        print(f"  ✓ HMAC will fail on receiver side")
        
        return bytes(modified)
    
    def _attack_replay(self, data: bytes, direction: str) -> bytes:
        """Attack: Store message and replay it"""
        # Store the captured message
        self.captured_messages.append((data, direction))
        
        print(f"Attack strategy: Capture and replay message")
        print(f"  ✓ Message captured (total: {len(self.captured_messages)})")
        
        # If we have a previous message, replay it
        if len(self.captured_messages) > 1:
            prev_msg, prev_dir = self.captured_messages[-2]
            if prev_dir == direction:
                print(f"  ✓ Replaying previously captured message from same direction")
                print(f"  ✓ Round number check will fail (replay detection)")
                return prev_msg
        
        print(f"  ℹ Waiting for another message to replay")
        return data
    
    def _attack_reorder(self, data: bytes, direction: str) -> bytes:
        """Attack: Reorder messages"""
        self.captured_messages.append((data, direction))
        
        print(f"Attack strategy: Reorder messages")
        print(f"  ✓ Message captured (total: {len(self.captured_messages)})")
        
        # If we have 2+ messages from same direction, send them out of order
        same_dir_msgs = [msg for msg, d in self.captured_messages if d == direction]
        if len(same_dir_msgs) >= 2:
            print(f"  ✓ Sending older message instead of current one")
            print(f"  ✓ Round number will be out of sequence")
            return same_dir_msgs[-2]  # Send second-to-last message
        
        print(f"  ℹ Need more messages to reorder")
        return data
    
    def _attack_key_desync(self, data: bytes) -> bytes:
        """Attack: Modify round number to cause key desynchronization"""
        print("Attack strategy: Modify round number to desynchronize keys")
        
        if len(data) < 23:  # Minimum header size
            print("  Message too short")
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
    
    def _cleanup_sockets(self, sock1: socket.socket, sock2: socket.socket):
        """Close both sockets"""
        try:
            sock1.close()
        except:
            pass
        try:
            sock2.close()
        except:
            pass
        self.running = False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Man-in-the-Middle Attacker for Secure Communication Protocol',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  1 - Incorrect HMAC: Tamper with message content
  2 - Replay attacks: Replay captured encrypted messages  
  3 - Message reordering: Send messages out of order
  4 - Key desynchronization: Modify round numbers to desync keys

Example Usage:
  # Start real server on port 9999
  python server.py --port 9999 --key <hex_key>
  
  # Start attacker proxy on port 8888 (clients connect here)
  python attacks.py --attack 1 --client-port 8888 --server-port 9999
  
  # Connect client to attacker's port (not real server)
  python client.py --port 8888 --key <hex_key> -i
  
  # Send a message - attacker will intercept and modify it
  > Hello server
        """
    )
    
    parser.add_argument('--attack', choices=['1', '2', '3', '4'], required=True,
                        help='Attack type: 1=Incorrect HMAC, 2=Replay, 3=Reorder, 4=Key desync')
    parser.add_argument('--client-port', type=int, default=8888,
                        help='Port for client to connect to (default: 8888)')
    parser.add_argument('--server-host', default='localhost',
                        help='Real server host (default: localhost)')
    parser.add_argument('--server-port', type=int, default=9999,
                        help='Real server port (default: 9999)')
    
    args = parser.parse_args()
    
    # Display attack info
    attack_name = MITMAttacker.ATTACK_TYPES.get(args.attack, "Unknown")
    print("\n" + "="*70)
    print("  MAN-IN-THE-MIDDLE ATTACKER")
    print("="*70)
    print(f"Attack Type: {attack_name}")
    print(f"Client connects to: localhost:{args.client_port}")
    print(f"Attacker forwards to: {args.server_host}:{args.server_port}")
    print("\nInstructions:")
    print(f"  1. Start the real server: python server.py --port {args.server_port} --key <key>")
    print(f"  2. This attacker is listening on port {args.client_port}")
    print(f"  3. Start client: python client.py --port {args.client_port} --key <key> -i")
    print(f"  4. Send messages - attacker will intercept and modify")
    print("="*70 + "\n")
    
    # Create and start attacker
    attacker = MITMAttacker(
        client_port=args.client_port,
        server_host=args.server_host,
        server_port=args.server_port,
        attack_type=args.attack
    )
    
    try:
        attacker.start()
    except KeyboardInterrupt:
        print("\n\nShutting down attacker...")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
