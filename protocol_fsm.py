"""
Protocol Finite State Machine (FSM) for Secure Communication Protocol
Manages protocol states and valid state transitions for both client and server.

Message Flow:
1. CLIENT_HELLO (opcode 10) Client → Server
2. SERVER_CHALLENGE (opcode 20) Server → Client
3. CLIENT_DATA (opcode 30) Client → Server
4. SERVER_AGGR_RESPONSE (opcode 40) Server → Client

Error Handling:
- KEY_DESYNC_ERROR (opcode 50) - Key synchronization error
- TERMINATE (opcode 60) - Connection termination
"""

from enum import Enum, auto
from typing import Dict, Set, Optional, Callable, Any
import struct
import time
import os
from dataclasses import dataclass, field

from crypto_utils import (
    generate_key, generate_session_id, derive_keys, derive_directional_keys, hash_data,
    create_challenge, create_response, verify_response,
    SecureMessage, CryptoError, get_timestamp,
    evolve_c2s_keys, evolve_s2c_keys
)


class ProtocolState(Enum):
    """Protocol states for the FSM"""
    INIT = auto()              # Initial state
    HELLO_SENT = auto()        # Client: sent CLIENT_HELLO, waiting for SERVER_CHALLENGE
    HELLO_RECEIVED = auto()    # Server: received CLIENT_HELLO, sending SERVER_CHALLENGE
    CHALLENGE_SENT = auto()    # Server: sent challenge, waiting for CLIENT_DATA
    CHALLENGE_RECEIVED = auto() # Client: received challenge, preparing CLIENT_DATA
    DATA_SENT = auto()         # Client: sent CLIENT_DATA, waiting for SERVER_AGGR_RESPONSE
    ESTABLISHED = auto()       # Session fully established, ready for data
    DATA_TRANSFER = auto()     # Actively transferring data
    CLOSING = auto()           # Initiating close
    CLOSED = auto()            # Session closed
    ERROR = auto()             # Error state (KEY_DESYNC_ERROR)


class Opcode(Enum):
    """Message opcodes used in the protocol"""
    CLIENT_HELLO = 10          # Client → Server: Initial hello
    SERVER_CHALLENGE = 20      # Server → Client: Challenge with server random
    CLIENT_DATA = 30           # Client → Server: Challenge response + key confirmation
    SERVER_AGGR_RESPONSE = 40  # Server → Client: Aggregated response (auth result)
    KEY_DESYNC_ERROR = 50      # Error: Key synchronization failure
    TERMINATE = 60             # Terminate connection


# Keep MessageType for backward compatibility
MessageType = Opcode


class KeyDesyncError(Exception):
    """Exception for key synchronization errors"""
    pass


@dataclass
class ProtocolMessage:
    """Represents a protocol message"""
    msg_type: Opcode
    payload: bytes
    sequence_number: int = 0
    timestamp: int = field(default_factory=get_timestamp)
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes"""
        header = struct.pack(
            '>BIi',
            self.msg_type.value,
            self.sequence_number,
            self.timestamp
        )
        length = struct.pack('>I', len(self.payload))
        return header + length + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ProtocolMessage':
        """Deserialize message from bytes"""
        if len(data) < 13:  # 1 + 4 + 4 + 4 = 13 bytes header
            raise ValueError("Message too short")
        
        msg_type_val, seq_num, timestamp = struct.unpack('>BIi', data[:9])
        length = struct.unpack('>I', data[9:13])[0]
        payload = data[13:13+length]
        
        return cls(
            msg_type=Opcode(msg_type_val),
            payload=payload,
            sequence_number=seq_num,
            timestamp=timestamp
        )


class StateTransitionError(Exception):
    """Exception for invalid state transitions"""
    pass


class ProtocolFSM:
    """
    Finite State Machine for the secure communication protocol.
    Manages state transitions and validates protocol flow.
    """
    
    # Valid state transitions for client
    CLIENT_TRANSITIONS: Dict[ProtocolState, Set[ProtocolState]] = {
        ProtocolState.INIT: {ProtocolState.HELLO_SENT},
        ProtocolState.HELLO_SENT: {ProtocolState.CHALLENGE_RECEIVED, ProtocolState.ERROR},
        ProtocolState.CHALLENGE_RECEIVED: {ProtocolState.DATA_SENT, ProtocolState.ERROR},
        ProtocolState.DATA_SENT: {ProtocolState.ESTABLISHED, ProtocolState.ERROR},
        ProtocolState.ESTABLISHED: {ProtocolState.DATA_TRANSFER, ProtocolState.CLOSING},
        ProtocolState.DATA_TRANSFER: {ProtocolState.DATA_TRANSFER, ProtocolState.CLOSING},
        ProtocolState.CLOSING: {ProtocolState.CLOSED},
        ProtocolState.CLOSED: set(),
        ProtocolState.ERROR: {ProtocolState.INIT, ProtocolState.CLOSED},
    }
    
    # Valid state transitions for server
    SERVER_TRANSITIONS: Dict[ProtocolState, Set[ProtocolState]] = {
        ProtocolState.INIT: {ProtocolState.HELLO_RECEIVED},
        ProtocolState.HELLO_RECEIVED: {ProtocolState.CHALLENGE_SENT, ProtocolState.ERROR},
        ProtocolState.CHALLENGE_SENT: {ProtocolState.ESTABLISHED, ProtocolState.ERROR},
        ProtocolState.ESTABLISHED: {ProtocolState.DATA_TRANSFER, ProtocolState.CLOSING},
        ProtocolState.DATA_TRANSFER: {ProtocolState.DATA_TRANSFER, ProtocolState.CLOSING},
        ProtocolState.CLOSING: {ProtocolState.CLOSED},
        ProtocolState.CLOSED: set(),
        ProtocolState.ERROR: {ProtocolState.INIT, ProtocolState.CLOSED},
    }
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.state = ProtocolState.INIT
        self.transitions = self.SERVER_TRANSITIONS if is_server else self.CLIENT_TRANSITIONS
        self.state_handlers: Dict[ProtocolState, Callable] = {}
        self.transition_callbacks: list = []
        self.error_message: Optional[str] = None
        
        # Session data
        self.session_id: Optional[bytes] = None
        self.pre_shared_key: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.encryption_key: Optional[bytes] = None
        self.mac_key: Optional[bytes] = None
        self.secure_message: Optional[SecureMessage] = None
        self.peer_public_data: Optional[bytes] = None
        self.challenge: Optional[bytes] = None
        self.sequence_number: int = 0
    
    def set_pre_shared_key(self, key: bytes):
        """Set the pre-shared secret key"""
        self.pre_shared_key = key
    
    def transition_to(self, new_state: ProtocolState) -> bool:
        """
        Attempt to transition to a new state.
        
        Args:
            new_state: Target state
        
        Returns:
            True if transition successful, False otherwise
        """
        if new_state not in self.transitions.get(self.state, set()):
            raise StateTransitionError(
                f"Invalid transition: {self.state.name} -> {new_state.name}"
            )
        
        old_state = self.state
        self.state = new_state
        
        # Notify callbacks
        for callback in self.transition_callbacks:
            callback(old_state, new_state)
        
        return True
    
    def add_transition_callback(self, callback: Callable[[ProtocolState, ProtocolState], None]):
        """Add a callback to be called on state transitions"""
        self.transition_callbacks.append(callback)
    
    def register_handler(self, state: ProtocolState, handler: Callable):
        """Register a handler for a specific state"""
        self.state_handlers[state] = handler
    
    def get_state(self) -> ProtocolState:
        """Get current state"""
        return self.state
    
    def is_established(self) -> bool:
        """Check if session is established and ready for data transfer"""
        return self.state in {ProtocolState.ESTABLISHED, ProtocolState.DATA_TRANSFER}
    
    def is_error(self) -> bool:
        """Check if FSM is in error state"""
        return self.state == ProtocolState.ERROR
    
    def reset(self):
        """Reset FSM to initial state"""
        self.state = ProtocolState.INIT
        self.error_message = None
        self.session_id = None
        self.session_key = None
        self.encryption_key = None
        self.mac_key = None
        self.secure_message = None
        self.peer_public_data = None
        self.challenge = None
        self.sequence_number = 0
    
    def set_error(self, message: str):
        """Set error state with message"""
        self.error_message = message
        self.state = ProtocolState.ERROR
    
    def create_key_desync_error(self, reason: str = "") -> ProtocolMessage:
        """Create KEY_DESYNC_ERROR message (opcode 50)"""
        self.sequence_number += 1
        return ProtocolMessage(
            msg_type=Opcode.KEY_DESYNC_ERROR,
            payload=reason.encode('utf-8'),
            sequence_number=self.sequence_number
        )
    
    def create_terminate(self, reason: str = "") -> ProtocolMessage:
        """Create TERMINATE message (opcode 60)"""
        self.sequence_number += 1
        return ProtocolMessage(
            msg_type=Opcode.TERMINATE,
            payload=reason.encode('utf-8'),
            sequence_number=self.sequence_number
        )


class ClientProtocol(ProtocolFSM):
    """
    Client-side protocol implementation.
    
    Message Flow:
    1. Send CLIENT_HELLO (opcode 10)
    2. Receive SERVER_CHALLENGE (opcode 20)
    3. Send CLIENT_DATA (opcode 30)
    4. Receive SERVER_AGGR_RESPONSE (opcode 40)
    """
    
    def __init__(self, pre_shared_key: bytes):
        super().__init__(is_server=False)
        self.pre_shared_key = pre_shared_key
        self.client_random: Optional[bytes] = None
        self.server_random: Optional[bytes] = None
    
    def create_hello(self) -> ProtocolMessage:
        """
        Step 1: Create CLIENT_HELLO message (opcode 10) to initiate connection.
        
        Payload: client_random (32 bytes) + session_id (16 bytes) + protocol_version (2 bytes)
        """
        if self.state != ProtocolState.INIT:
            raise StateTransitionError(f"Cannot send CLIENT_HELLO in state {self.state.name}")
        
        self.client_random = os.urandom(32)  # 32 random bytes
        self.session_id = generate_session_id()
        
        # Payload: client_random + session_id + protocol_version
        protocol_version = struct.pack('>H', 1)  # Version 1.0
        payload = self.client_random + self.session_id + protocol_version
        
        self.sequence_number += 1
        self.transition_to(ProtocolState.HELLO_SENT)
        
        return ProtocolMessage(
            msg_type=Opcode.CLIENT_HELLO,
            payload=payload,
            sequence_number=self.sequence_number
        )
    
    def process_server_challenge(self, message: ProtocolMessage) -> ProtocolMessage:
        """
        Step 2→3: Process SERVER_CHALLENGE (opcode 20) and create CLIENT_DATA (opcode 30).
        
        Receives: server_random + session_id + challenge
        Sends: challenge_response + key_confirmation
        """
        if self.state != ProtocolState.HELLO_SENT:
            raise StateTransitionError(f"Unexpected SERVER_CHALLENGE in state {self.state.name}")
        
        if message.msg_type != Opcode.SERVER_CHALLENGE:
            if message.msg_type == Opcode.KEY_DESYNC_ERROR:
                raise KeyDesyncError(message.payload.decode('utf-8', errors='replace'))
            raise StateTransitionError(f"Expected SERVER_CHALLENGE, got {message.msg_type.name}")
        
        # Parse server random (32 bytes), session ID (16 bytes), and challenge (32 bytes)
        self.server_random = message.payload[:32]
        received_session_id = message.payload[32:48]
        self.challenge = message.payload[48:80]
        
        # Verify session ID matches
        if received_session_id != self.session_id:
            self.set_error("Session ID mismatch")
            raise KeyDesyncError("Session ID mismatch")
        
        self.transition_to(ProtocolState.CHALLENGE_RECEIVED)
        
        # Derive directional keys from master key Ki
        # Each client Ci shares a master key Ki with the server
        c2s_enc, c2s_mac, s2c_enc, s2c_mac = derive_directional_keys(self.pre_shared_key)
        
        # Client sends with C2S keys (Client → Server)
        self.encryption_key = c2s_enc  # C2S_Enc_0 = H(Ki || "C2S-ENC")
        self.mac_key = c2s_mac          # C2S_Mac_0 = H(Ki || "C2S-MAC")
        
        # Store S2C keys for receiving (Server → Client)
        self.s2c_encryption_key = s2c_enc  # S2C_Enc_0 = H(Ki || "S2C-ENC")
        self.s2c_mac_key = s2c_mac          # S2C_Mac_0 = H(Ki || "S2C-MAC")
        
        # Derive client_id from session_id (use first byte as client ID)
        self.client_id = self.session_id[0]  # Single byte (0-255)
        
        # Create secure message handler for sending (client uses C2S keys)
        self.secure_message = SecureMessage(
            self.encryption_key, self.mac_key, self.client_id, direction=0
        )
        
        # Create challenge response using pre-shared key
        challenge_response = create_response(self.challenge, self.pre_shared_key)
        
        # Create key confirmation (hash of derived keys)
        key_confirmation = hash_data(self.encryption_key + self.mac_key)
        
        self.transition_to(ProtocolState.DATA_SENT)
        self.sequence_number += 1
        
        # CLIENT_DATA payload: challenge_response + key_confirmation
        return ProtocolMessage(
            msg_type=Opcode.CLIENT_DATA,
            payload=challenge_response + key_confirmation,
            sequence_number=self.sequence_number
        )
    
    def process_server_response(self, message: ProtocolMessage) -> bool:
        """
        Step 4: Process SERVER_AGGR_RESPONSE (opcode 40).
        
        Receives: authentication result + optional data
        Returns: True if authentication successful
        """
        if self.state != ProtocolState.DATA_SENT:
            raise StateTransitionError(f"Unexpected SERVER_AGGR_RESPONSE in state {self.state.name}")
        
        if message.msg_type == Opcode.KEY_DESYNC_ERROR:
            self.set_error("Key synchronization error")
            raise KeyDesyncError(message.payload.decode('utf-8', errors='replace'))
        
        if message.msg_type != Opcode.SERVER_AGGR_RESPONSE:
            raise StateTransitionError(f"Expected SERVER_AGGR_RESPONSE, got {message.msg_type.name}")
        
        # Parse response: status (1 byte) + server_key_confirmation (32 bytes)
        if len(message.payload) < 33:
            self.set_error("Invalid SERVER_AGGR_RESPONSE payload")
            return False
        
        status = message.payload[0]
        server_key_confirmation = message.payload[1:33]
        
        # Verify server's key confirmation using S2C keys (server sends with S2C keys)
        # Server confirmation: hash(s2c_mac + s2c_enc)
        expected_confirmation = hash_data(self.s2c_mac_key + self.s2c_encryption_key)
        if server_key_confirmation != expected_confirmation:
            self.set_error("Server key confirmation mismatch")
            return False
        
        # Create receiver for S2C messages (server→client)
        # Receiver direction should match the incoming message direction (S2C = direction 1)
        self.secure_message_receiver = SecureMessage(
            self.s2c_encryption_key, self.s2c_mac_key, self.client_id, direction=1
        )
        
        if status == 0x01:  # Success
            self.transition_to(ProtocolState.ESTABLISHED)
            return True
        else:
            self.set_error("Authentication failed")
            return False
    
    def create_data_message(self, data: bytes) -> bytes:
        """Create encrypted data message for transfer phase"""
        if not self.is_established():
            raise StateTransitionError(f"Cannot send data in state {self.state.name}")
        
        if self.state == ProtocolState.ESTABLISHED:
            self.transition_to(ProtocolState.DATA_TRANSFER)
        
        return self.secure_message.create_message(data, Opcode.CLIENT_DATA.value)
    
    def process_data_message(self, encrypted_data: bytes) -> bytes:
        """Process received encrypted data message"""
        if not self.is_established():
            raise StateTransitionError(f"Cannot receive data in state {self.state.name}")
        
        # Use S2C receiver for messages from server
        payload, opcode, round_num = self.secure_message_receiver.parse_message(encrypted_data)
        return payload
    
    def create_close(self) -> ProtocolMessage:
        """Create TERMINATE message (opcode 60)"""
        self.transition_to(ProtocolState.CLOSING)
        self.sequence_number += 1
        
        return ProtocolMessage(
            msg_type=Opcode.TERMINATE,
            payload=b"Client disconnect",
            sequence_number=self.sequence_number
        )
    
    def process_close_ack(self, message: ProtocolMessage):
        """Process terminate acknowledgment"""
        if message.msg_type == Opcode.TERMINATE:
            self.transition_to(ProtocolState.CLOSED)


class ServerProtocol(ProtocolFSM):
    """
    Server-side protocol implementation.
    
    Message Flow:
    1. Receive CLIENT_HELLO (opcode 10)
    2. Send SERVER_CHALLENGE (opcode 20)
    3. Receive CLIENT_DATA (opcode 30)
    4. Send SERVER_AGGR_RESPONSE (opcode 40)
    """
    
    def __init__(self, pre_shared_key: bytes):
        super().__init__(is_server=True)
        self.pre_shared_key = pre_shared_key
        self.client_random: Optional[bytes] = None
        self.server_random: Optional[bytes] = None
    
    def process_client_hello(self, message: ProtocolMessage) -> ProtocolMessage:
        """
        Step 1→2: Process CLIENT_HELLO (opcode 10) and create SERVER_CHALLENGE (opcode 20).
        
        Receives: client_random + session_id + protocol_version
        Sends: server_random + session_id + challenge
        """
        if self.state != ProtocolState.INIT:
            raise StateTransitionError(f"Unexpected CLIENT_HELLO in state {self.state.name}")
        
        if message.msg_type != Opcode.CLIENT_HELLO:
            raise StateTransitionError(f"Expected CLIENT_HELLO, got {message.msg_type.name}")
        
        # Parse client random, session ID, and protocol version
        self.client_random = message.payload[:32]
        self.session_id = message.payload[32:48]
        protocol_version = struct.unpack('>H', message.payload[48:50])[0]
        
        # Generate server random and challenge
        self.server_random = os.urandom(32)  # 32 random bytes
        self.challenge = create_challenge()
        
        self.transition_to(ProtocolState.HELLO_RECEIVED)
        self.transition_to(ProtocolState.CHALLENGE_SENT)
        self.sequence_number += 1
        
        # SERVER_CHALLENGE payload: server_random + session_id + challenge
        payload = self.server_random + self.session_id + self.challenge
        
        return ProtocolMessage(
            msg_type=Opcode.SERVER_CHALLENGE,
            payload=payload,
            sequence_number=self.sequence_number
        )
    
    def process_client_data(self, message: ProtocolMessage) -> ProtocolMessage:
        """
        Step 3→4: Process CLIENT_DATA (opcode 30) and create SERVER_AGGR_RESPONSE (opcode 40).
        
        Receives: challenge_response + key_confirmation
        Sends: status + server_key_confirmation
        """
        if self.state != ProtocolState.CHALLENGE_SENT:
            raise StateTransitionError(f"Unexpected CLIENT_DATA in state {self.state.name}")
        
        if message.msg_type != Opcode.CLIENT_DATA:
            raise StateTransitionError(f"Expected CLIENT_DATA, got {message.msg_type.name}")
        
        # Parse challenge response (32 bytes) and key confirmation (32 bytes)
        challenge_response = message.payload[:32]
        client_key_confirmation = message.payload[32:64]
        
        # Verify challenge response
        if not verify_response(self.challenge, challenge_response, self.pre_shared_key):
            self.set_error("Challenge response verification failed")
            self.sequence_number += 1
            return ProtocolMessage(
                msg_type=Opcode.KEY_DESYNC_ERROR,
                payload=b"Invalid challenge response - key mismatch",
                sequence_number=self.sequence_number
            )
        
        # Derive directional keys from master key Ki
        # Each client Ci shares a master key Ki with the server
        c2s_enc, c2s_mac, s2c_enc, s2c_mac = derive_directional_keys(self.pre_shared_key)
        
        # Server receives with C2S keys (Client → Server)
        self.c2s_encryption_key = c2s_enc  # C2S_Enc_0 = H(Ki || "C2S-ENC")
        self.c2s_mac_key = c2s_mac          # C2S_Mac_0 = H(Ki || "C2S-MAC")
        
        # Derive client_id from session_id (use first byte as client ID)
        self.client_id = self.session_id[0]  # Single byte (0-255)
        
        # Create receiver for C2S messages (client→server)
        # Receiver direction should match the incoming message direction (C2S = direction 0)
        self.secure_message_receiver = SecureMessage(
            self.c2s_encryption_key, self.c2s_mac_key, self.client_id, direction=0
        )
        
        # Server sends with S2C keys (Server → Client)
        self.encryption_key = s2c_enc  # S2C_Enc_0 = H(Ki || "S2C-ENC")
        self.mac_key = s2c_mac          # S2C_Mac_0 = H(Ki || "S2C-MAC")
        
        # Verify client's key confirmation (client derived C2S keys)
        expected_confirmation = hash_data(c2s_enc + c2s_mac)
        if client_key_confirmation != expected_confirmation:
            self.set_error("Key confirmation mismatch")
            self.sequence_number += 1
            return ProtocolMessage(
                msg_type=Opcode.KEY_DESYNC_ERROR,
                payload=b"Key confirmation mismatch",
                sequence_number=self.sequence_number
            )
        
        # Create secure message handler for sending (server uses S2C keys)
        self.secure_message = SecureMessage(
            self.encryption_key, self.mac_key, self.client_id, direction=1
        )
        
        self.transition_to(ProtocolState.ESTABLISHED)
        self.sequence_number += 1
        
        # SERVER_AGGR_RESPONSE: status (1 byte, 0x01=success) + server_key_confirmation
        # Server uses reversed order for its confirmation (mac_key + encryption_key)
        server_key_confirmation = hash_data(self.mac_key + self.encryption_key)
        payload = bytes([0x01]) + server_key_confirmation
        
        return ProtocolMessage(
            msg_type=Opcode.SERVER_AGGR_RESPONSE,
            payload=payload,
            sequence_number=self.sequence_number
        )
    
    def create_data_message(self, data: bytes) -> bytes:
        """Create encrypted data message for transfer phase"""
        if not self.is_established():
            raise StateTransitionError(f"Cannot send data in state {self.state.name}")
        
        if self.state == ProtocolState.ESTABLISHED:
            self.transition_to(ProtocolState.DATA_TRANSFER)
        
        return self.secure_message.create_message(data, Opcode.SERVER_AGGR_RESPONSE.value)
    
    def process_data_message(self, encrypted_data: bytes) -> bytes:
        """Process received encrypted data message"""
        if not self.is_established():
            raise StateTransitionError(f"Cannot receive data in state {self.state.name}")
        
        # Use C2S receiver for messages from client
        payload, msg_type, seq_num = self.secure_message_receiver.parse_message(encrypted_data)
        return payload
    
    def process_close(self, message: ProtocolMessage) -> ProtocolMessage:
        """Process TERMINATE request and send acknowledgment"""
        self.transition_to(ProtocolState.CLOSING)
        self.sequence_number += 1
        
        return ProtocolMessage(
            msg_type=Opcode.TERMINATE,
            payload=b"Connection terminated",
            sequence_number=self.sequence_number
        )

if __name__ == "__main__":
    print("=== Protocol FSM Test ===\n")
    
    # Shared secret (in practice, this would be pre-distributed securely)
    shared_secret = generate_key()
    print(f"Pre-shared key: {shared_secret.hex()[:32]}...\n")
    
    # Create client and server protocols
    client = ClientProtocol(shared_secret)
    server = ServerProtocol(shared_secret)
    
    # Add transition logging
    client.add_transition_callback(lambda o, n: print(f"  [Client] {o.name} -> {n.name}"))
    server.add_transition_callback(lambda o, n: print(f"  [Server] {o.name} -> {n.name}"))
    
    print("1. Client sends CLIENT_HELLO (opcode 10)")
    hello = client.create_hello()
    print(f"   Session ID: {client.session_id.hex()[:16]}...")
    print(f"   Opcode: {hello.msg_type.value}")
    
    print("\n2. Server processes CLIENT_HELLO, sends SERVER_CHALLENGE (opcode 20)")
    challenge = server.process_client_hello(hello)
    print(f"   Opcode: {challenge.msg_type.value}")
    
    print("\n3. Client processes SERVER_CHALLENGE, sends CLIENT_DATA (opcode 30)")
    client_data = client.process_server_challenge(challenge)
    print(f"   Opcode: {client_data.msg_type.value}")
    
    print("\n4. Server processes CLIENT_DATA, sends SERVER_AGGR_RESPONSE (opcode 40)")
    server_response = server.process_client_data(client_data)
    print(f"   Opcode: {server_response.msg_type.value}")
    
    print("\n5. Client processes SERVER_AGGR_RESPONSE")
    success = client.process_server_response(server_response)
    print(f"   Authentication successful: {success}")
    
    print("\n6. Data transfer phase")
    message = b"Hello, secure world!"
    encrypted = client.create_data_message(message)
    print(f"   Original: {message}")
    print(f"   Encrypted length: {len(encrypted)} bytes")
    
    decrypted = server.process_data_message(encrypted)
    print(f"   Decrypted: {decrypted}")
    
    # Server responds
    response = b"Message received securely!"
    encrypted_response = server.create_data_message(response)
    decrypted_response = client.process_data_message(encrypted_response)
    print(f"   Server response: {decrypted_response}")
    
    print("\n7. Terminate connection (opcode 60)")
    terminate_msg = client.create_close()
    print(f"   Opcode: {terminate_msg.msg_type.value}")
    terminate_ack = server.process_close(terminate_msg)
    client.process_close_ack(terminate_ack)
    
    print(f"\nFinal states:")
    print(f"   Client: {client.get_state().name}")
    print(f"   Server: {server.get_state().name}")
