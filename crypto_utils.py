"""
Cryptographic Utilities for Secure Communication Protocol
Provides symmetric encryption (AES-128-CBC), HMAC authentication, key derivation,
nonce management, and PKCS#7 padding.

Security Model: Encrypt-then-MAC
1. Apply PKCS#7 padding
2. Encrypt with AES-128-CBC
3. Compute HMAC over (Header || Ciphertext)
4. Verify HMAC BEFORE decryption
"""

import os
import hashlib
import hmac
import struct
import time
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Constants
AES_KEY_SIZE = 16  # 128-bit key for AES-128
IV_SIZE = 16       # 128-bit IV for AES-CBC
MAC_SIZE = 32      # 256-bit HMAC-SHA256
BLOCK_SIZE = 16    # AES block size for PKCS#7 padding
TIMESTAMP_TOLERANCE = 300  # 5 minutes tolerance for timestamp validation


class CryptoError(Exception):
    """Custom exception for cryptographic errors"""
    pass


class NonceManager:
    """
    Manages nonces to prevent replay attacks.
    Tracks used nonces and validates freshness using timestamps.
    """
    
    def __init__(self, window_size: int = 1000):
        self.used_nonces = set()
        self.window_size = window_size
        self.counter = 0
    
    def generate_nonce(self) -> bytes:
        """Generate a unique nonce combining counter and random bytes"""
        self.counter += 1
        # Combine counter (4 bytes) with random bytes (12 bytes) for 16-byte IV
        counter_bytes = struct.pack('>I', self.counter % (2**32))
        random_bytes = os.urandom(12)
        iv = counter_bytes + random_bytes
        return iv
    
    def validate_nonce(self, nonce: bytes) -> bool:
        """
        Validate that a nonce hasn't been used before.
        Returns True if nonce is fresh, False if it's a replay.
        """
        if nonce in self.used_nonces:
            return False
        
        # Add to used nonces
        self.used_nonces.add(nonce)
        
        # Clean up old nonces if window is exceeded
        if len(self.used_nonces) > self.window_size:
            # Remove oldest entries (convert to list, sort, remove oldest)
            self.used_nonces = set(list(self.used_nonces)[-self.window_size//2:])
        
        return True
    
    def reset(self):
        """Reset the nonce manager"""
        self.used_nonces.clear()
        self.counter = 0


def generate_key() -> bytes:
    """Generate a random 128-bit AES key"""
    return os.urandom(AES_KEY_SIZE)


def generate_session_id() -> bytes:
    """Generate a unique session identifier"""
    return os.urandom(16)


def derive_keys(master_secret: bytes, salt: bytes, info: bytes = b"session_keys") -> Tuple[bytes, bytes]:
    """
    Derive encryption and MAC keys from a master secret using HKDF.
    
    Args:
        master_secret: The shared secret
        salt: Random salt for key derivation
        info: Context information for key derivation
    
    Returns:
        Tuple of (encryption_key, mac_key)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48,  # 16 bytes for AES-128 encryption + 32 bytes for HMAC-SHA256
        salt=salt,
        info=info,
        backend=default_backend()
    )
    derived_key = hkdf.derive(master_secret)
    encryption_key = derived_key[:16]  # AES-128 key
    mac_key = derived_key[16:]          # HMAC key
    return encryption_key, mac_key


def derive_directional_keys(master_key: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Derive directional keys from a master key using hash-based key derivation.
    Each client Ci shares a master key Ki with the server.
    
    Client → Server Keys:
        C2S_Enc = H(Ki || "C2S-ENC")
        C2S_Mac = H(Ki || "C2S-MAC")
    
    Server → Client Keys:
        S2C_Enc = H(Ki || "S2C-ENC")
        S2C_Mac = H(Ki || "S2C-MAC")
    
    Args:
        master_key: The shared master key Ki (16 bytes for AES-128)
    
    Returns:
        Tuple of (c2s_enc_key, c2s_mac_key, s2c_enc_key, s2c_mac_key)
    """
    # Client → Server Encryption Key: H(Ki || "C2S-ENC")
    c2s_enc = hash_data(master_key + b"C2S-ENC")[:16]  # Use first 16 bytes for AES-128
    
    # Client → Server MAC Key: H(Ki || "C2S-MAC")
    c2s_mac = hash_data(master_key + b"C2S-MAC")  # Full 32 bytes for HMAC-SHA256
    
    # Server → Client Encryption Key: H(Ki || "S2C-ENC")
    s2c_enc = hash_data(master_key + b"S2C-ENC")[:16]  # Use first 16 bytes for AES-128
    
    # Server → Client MAC Key: H(Ki || "S2C-MAC")
    s2c_mac = hash_data(master_key + b"S2C-MAC")  # Full 32 bytes for HMAC-SHA256
    
    return c2s_enc, c2s_mac, s2c_enc, s2c_mac


def evolve_c2s_keys(c2s_enc: bytes, c2s_mac: bytes, ciphertext: bytes, iv: bytes) -> Tuple[bytes, bytes]:
    """
    Evolve Client→Server keys for the next round.
    
    Key Evolution (Round R → R+1):
        C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
        C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
    
    Args:
        c2s_enc: Current C2S encryption key (16 bytes)
        c2s_mac: Current C2S MAC key (32 bytes)
        ciphertext: Ciphertext from round R
        iv: IV/Nonce from round R (16 bytes)
    
    Returns:
        Tuple of (new_c2s_enc, new_c2s_mac)
    """
    # C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
    new_c2s_enc = hash_data(c2s_enc + ciphertext)[:16]  # First 16 bytes for AES-128
    
    # C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
    new_c2s_mac = hash_data(c2s_mac + iv)  # Full 32 bytes for HMAC-SHA256
    
    return new_c2s_enc, new_c2s_mac


def evolve_s2c_keys(s2c_enc: bytes, s2c_mac: bytes, aggregated_data: bytes, status_code: bytes) -> Tuple[bytes, bytes]:
    """
    Evolve Server→Client keys for the next round.
    
    Key Evolution (Round R → R+1):
        S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
        S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
    
    Args:
        s2c_enc: Current S2C encryption key (16 bytes)
        s2c_mac: Current S2C MAC key (32 bytes)
        aggregated_data: Aggregated/response data from round R
        status_code: Status code from round R
    
    Returns:
        Tuple of (new_s2c_enc, new_s2c_mac)
    """
    # S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
    new_s2c_enc = hash_data(s2c_enc + aggregated_data)[:16]  # First 16 bytes for AES-128
    
    # S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
    new_s2c_mac = hash_data(s2c_mac + status_code)  # Full 32 bytes for HMAC-SHA256
    
    return new_s2c_enc, new_s2c_mac


def hash_data(data: bytes) -> bytes:
    """Compute SHA-256 hash of data"""
    return hashlib.sha256(data).digest()


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 of data using the given key"""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """Verify HMAC-SHA256 of data (constant-time comparison)"""
    computed_mac = compute_hmac(key, data)
    return hmac.compare_digest(computed_mac, expected_mac)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Apply PKCS#7 padding to data.
    
    Args:
        data: Data to pad
        block_size: Block size (16 bytes for AES)
    
    Returns:
        Padded data
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(padded_data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Args:
        padded_data: Padded data
        block_size: Block size (16 bytes for AES)
    
    Returns:
        Unpadded data
    
    Raises:
        CryptoError: If padding is invalid
    """
    if len(padded_data) == 0 or len(padded_data) % block_size != 0:
        raise CryptoError("Invalid padded data length")
    
    padding_length = padded_data[-1]
    
    # Validate padding
    if padding_length < 1 or padding_length > block_size:
        raise CryptoError("Invalid padding length")
    
    # Check all padding bytes
    for i in range(padding_length):
        if padded_data[-(i + 1)] != padding_length:
            raise CryptoError("Invalid PKCS#7 padding")
    
    return padded_data[:-padding_length]


def encrypt_aes_cbc(key: bytes, plaintext: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-128-CBC with PKCS#7 padding.
    
    Encryption Process:
    1. Apply PKCS#7 padding manually
    2. Generate fresh random IV (16 bytes)
    3. Encrypt padded plaintext using AES-128-CBC
    
    Args:
        key: 128-bit AES key
        plaintext: Data to encrypt
        iv: Optional 128-bit IV (generated if not provided)
    
    Returns:
        Tuple of (iv, ciphertext)
    
    Note: This provides confidentiality only. Use compute_hmac() for authentication.
    """
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(f"Invalid key size: {len(key)}, expected {AES_KEY_SIZE}")
    
    # Step 1: Apply PKCS#7 padding manually
    padded_plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    
    # Step 2: Generate fresh random IV
    if iv is None:
        iv = os.urandom(IV_SIZE)
    elif len(iv) != IV_SIZE:
        raise CryptoError(f"Invalid IV size: {len(iv)}, expected {IV_SIZE}")
    
    # Step 3: Encrypt using AES-128-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return iv, ciphertext


def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt data using AES-128-CBC and remove PKCS#7 padding.
    
    Decryption Process:
    1. Decrypt ciphertext using AES-128-CBC
    2. Remove PKCS#7 padding
    3. Validate plaintext format
    
    Args:
        key: 128-bit AES key
        iv: 128-bit IV used for encryption
        ciphertext: Encrypted data
    
    Returns:
        Decrypted plaintext
    
    Raises:
        CryptoError: If decryption or padding removal fails
    
    WARNING: This function should ONLY be called AFTER HMAC verification!
    """
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(f"Invalid key size: {len(key)}, expected {AES_KEY_SIZE}")
    
    if len(iv) != IV_SIZE:
        raise CryptoError(f"Invalid IV size: {len(iv)}, expected {IV_SIZE}")
    
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise CryptoError("Invalid ciphertext length")
    
    # Step 1: Decrypt using AES-128-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Step 2: Remove PKCS#7 padding
    plaintext = pkcs7_unpad(padded_plaintext, BLOCK_SIZE)
    
    return plaintext


def get_timestamp() -> int:
    """Get current Unix timestamp"""
    return int(time.time())


def validate_timestamp(timestamp: int, tolerance: int = TIMESTAMP_TOLERANCE) -> bool:
    """
    Validate that a timestamp is within acceptable range.
    
    Args:
        timestamp: Unix timestamp to validate
        tolerance: Maximum allowed difference in seconds
    
    Returns:
        True if timestamp is valid, False otherwise
    """
    current_time = get_timestamp()
    return abs(current_time - timestamp) <= tolerance


class SecureMessage:
    """
    Encapsulates a secure message with encryption, authentication, and replay protection.
    
    Uses Encrypt-then-MAC construction with AES-128-CBC + HMAC-SHA256.
    
    Message format:
    [Opcode (1B)][Client_ID (1B)][Round (4B)][Direction (1B)][IV (16B)][Ciphertext (var)][HMAC (32B)]
    
    The HMAC covers all preceding fields.
    
    Encryption (Sender Side):
    1. Construct plaintext payload
    2. Apply PKCS#7 padding manually
    3. Generate a fresh random IV (16 bytes)
    4. Encrypt padded plaintext using AES-128-CBC
    5. Construct message header fields
    6. Compute HMAC over (Header || Ciphertext)
    7. Transmit (Header || Ciphertext || HMAC)
    
    Decryption (Receiver Side):
    1. Verify round number and direction
    2. Verify HMAC before decryption
    3. If HMAC fails, terminate session
    4. Decrypt ciphertext using AES-128-CBC
    5. Remove PKCS#7 padding
    6. Validate plaintext format
    """
    
    HEADER_SIZE = 1 + 1 + 4 + 1 + 16  # opcode + client_id + round + direction + iv
    
    def __init__(self, encryption_key: bytes, mac_key: bytes, client_id: int, direction: int = 0):
        """
        Initialize secure message handler.
        
        Args:
            encryption_key: 128-bit key for AES-128-CBC
            mac_key: 256-bit key for HMAC-SHA256
            client_id: Client identifier (0-255)
            direction: 0 for client->server, 1 for server->client
        """
        if len(encryption_key) != AES_KEY_SIZE:
            raise CryptoError(f"Encryption key must be {AES_KEY_SIZE} bytes")
        if len(mac_key) < 16:
            raise CryptoError(f"MAC key must be at least 16 bytes")
        if client_id < 0 or client_id > 255:
            raise CryptoError(f"Client ID must be 0-255")
        
        self.encryption_key = encryption_key
        self.mac_key = mac_key
        self.client_id = client_id
        self.direction = direction
        self.round_number = 0  # Changed from sequence_number
        self.nonce_manager = NonceManager()
        self.last_received_round = 0  # Changed from last_received_seq
    
    def create_message(self, plaintext: bytes, opcode: int = 0) -> bytes:
        """
        Create a secure message with encryption and authentication.
        
        Message Format: [Opcode (1B)][Client_ID (1B)][Round (4B)][Direction (1B)][IV (16B)][Ciphertext (var)][HMAC (32B)]
        
        Encryption (Sender Side):
        1. Construct plaintext payload
        2. Apply PKCS#7 padding manually
        3. Generate a fresh random IV (16 bytes)
        4. Encrypt padded plaintext using AES-128-CBC
        5. Construct message header fields
        6. Compute HMAC over (Header || Ciphertext)
        7. Transmit (Header || Ciphertext || HMAC)
        8. Evolve keys for next round
        
        Args:
            plaintext: Data to send
            opcode: Message opcode (0-255)
        
        Returns:
            Complete secure message bytes
        """
        # Increment round number
        self.round_number += 1
        
        # Step 1: Construct plaintext payload (just the plaintext, no message_type prefix)
        payload = plaintext
        
        # Steps 2-4: Apply PKCS#7 padding, generate IV, encrypt using AES-128-CBC
        iv, ciphertext = encrypt_aes_cbc(self.encryption_key, payload)
        
        # Step 5: Construct message header fields
        # Format: [Opcode (1B)][Client_ID (1B)][Round (4B)][Direction (1B)][IV (16B)]
        header = (
            struct.pack('>B', opcode) +                 # 1 byte (opcode)
            struct.pack('>B', self.client_id) +         # 1 byte (client ID)
            struct.pack('>I', self.round_number) +      # 4 bytes (round number)
            struct.pack('>B', self.direction) +         # 1 byte (direction)
            iv                                          # 16 bytes (IV)
        )
        
        # Combine header and ciphertext
        message = header + ciphertext
        
        # Step 6: Compute HMAC over (Header || Ciphertext)
        mac = compute_hmac(self.mac_key, message)
        
        # Step 7: Transmit (Header || Ciphertext || HMAC)
        full_message = message + mac
        
        # Step 8: Evolve keys for next round
        if self.direction == 0:  # C2S (Client → Server)
            # C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
            # C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
            self.encryption_key, self.mac_key = evolve_c2s_keys(
                self.encryption_key, self.mac_key, ciphertext, iv
            )
        else:  # S2C (Server → Client)
            # S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
            # S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
            # Use plaintext as aggregated data and opcode as status
            status_code = struct.pack('>B', opcode)
            self.encryption_key, self.mac_key = evolve_s2c_keys(
                self.encryption_key, self.mac_key, plaintext, status_code
            )
        
        return full_message
    
    def parse_message(self, data: bytes) -> Tuple[bytes, int, int]:
        """
        Parse and verify a secure message.
        
        Message Format: [Opcode (1B)][Client_ID (1B)][Round (4B)][Direction (1B)][IV (16B)][Ciphertext (var)][HMAC (32B)]
        
        Decryption (Receiver Side):
        1. Verify round number and direction
        2. Verify HMAC before decryption
        3. If HMAC fails, terminate session
        4. Decrypt ciphertext using AES-128-CBC
        5. Remove PKCS#7 padding
        6. Validate plaintext format
        
        Args:
            data: Complete secure message bytes
        
        Returns:
            Tuple of (plaintext, opcode, round_number)
        
        Raises:
            CryptoError: If message verification fails
        """
        if len(data) < self.HEADER_SIZE + MAC_SIZE + BLOCK_SIZE:
            raise CryptoError("Message too short")
        
        # Extract MAC and message
        mac = data[-MAC_SIZE:]
        message = data[:-MAC_SIZE]
        
        # Parse header before HMAC verification (for round/direction check)
        # Format: [Opcode (1B)][Client_ID (1B)][Round (4B)][Direction (1B)][IV (16B)]
        opcode = struct.unpack('>B', message[0:1])[0]
        client_id = struct.unpack('>B', message[1:2])[0]
        round_number = struct.unpack('>I', message[2:6])[0]
        direction = struct.unpack('>B', message[6:7])[0]
        iv = message[7:23]
        ciphertext = message[23:]
        
        # Step 1: Verify client ID, round number and direction
        if client_id != self.client_id:
            raise CryptoError("Invalid client ID - possible reflection attack")
        
        # Verify direction (receiver's direction should match incoming message direction)
        if direction != self.direction:
            raise CryptoError(f"Invalid message direction - expected {self.direction}, got {direction}")
        
        # Verify round number (should be greater than last received)
        if round_number <= self.last_received_round:
            raise CryptoError(f"Invalid round number - possible replay or reorder attack (received {round_number}, expected > {self.last_received_round})")
        
        # Step 2: Verify HMAC before decryption (CRITICAL!)
        if not verify_hmac(self.mac_key, message, mac):
            # Step 3: If HMAC fails, terminate session
            raise CryptoError("HMAC verification failed - message integrity compromised. SESSION TERMINATED.")
        
        # HMAC verification passed - safe to decrypt
        
        # Step 4: Decrypt ciphertext using AES-128-CBC
        # Step 5: Remove PKCS#7 padding (done inside decrypt_aes_cbc)
        try:
            plaintext = decrypt_aes_cbc(self.encryption_key, iv, ciphertext)
        except CryptoError as e:
            raise CryptoError(f"Decryption failed: {e}")
        
        # Step 6: Validate plaintext format
        if len(plaintext) < 1:
            raise CryptoError("Invalid plaintext format - too short")
        
        # Update round number after successful verification
        self.last_received_round = round_number
        
        # Step 7: Evolve keys for next round after successful decryption
        if self.direction == 0:  # C2S (receiving client→server messages)
            # C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
            # C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
            self.encryption_key, self.mac_key = evolve_c2s_keys(
                self.encryption_key, self.mac_key, ciphertext, iv
            )
        else:  # S2C (receiving server→client messages)
            # S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
            # S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
            # Use plaintext as aggregated data and opcode as status
            status_code = struct.pack('>B', opcode)
            self.encryption_key, self.mac_key = evolve_s2c_keys(
                self.encryption_key, self.mac_key, plaintext, status_code
            )
        
        return plaintext, opcode, round_number
    
    def reset_sequence(self):
        """Reset round number (for new session)"""
        self.round_number = 0
        self.nonce_manager.reset()


def create_challenge() -> bytes:
    """Create a random challenge for authentication"""
    return os.urandom(32)


def create_response(challenge: bytes, shared_secret: bytes) -> bytes:
    """
    Create a response to an authentication challenge.
    
    Args:
        challenge: The challenge bytes
        shared_secret: Pre-shared secret or derived key
    
    Returns:
        Response bytes
    """
    return compute_hmac(shared_secret, challenge)


def verify_response(challenge: bytes, response: bytes, shared_secret: bytes) -> bool:
    """
    Verify a challenge response.
    
    Args:
        challenge: The original challenge
        response: The received response
        shared_secret: Pre-shared secret or derived key
    
    Returns:
        True if response is valid
    """
    expected_response = create_response(challenge, shared_secret)
    return hmac.compare_digest(expected_response, response)


# Password-based key derivation (for user authentication)
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a key from a password using HKDF.
    
    Args:
        password: User's password
        salt: Random salt (should be stored with the derived key)
    
    Returns:
        256-bit derived key
    """
    password_bytes = password.encode('utf-8')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"password_derived_key",
        backend=default_backend()
    )
    return hkdf.derive(password_bytes)


if __name__ == "__main__":
    # Test the cryptographic utilities
    print("=== Testing Crypto Utilities ===\n")
    
    # Test key generation
    key = generate_key()
    print(f"Generated key (hex): {key.hex()}")
    print(f"Key size: {len(key)} bytes (AES-128)\n")
    
    # Test PKCS#7 padding
    data = b"Hello"
    padded = pkcs7_pad(data)
    print(f"Original: {data} ({len(data)} bytes)")
    print(f"Padded: {padded.hex()} ({len(padded)} bytes)")
    unpadded = pkcs7_unpad(padded)
    print(f"Unpadded: {unpadded}")
    assert data == unpadded, "Padding/unpadding failed!"
    print("✓ PKCS#7 padding working\n")
    
    # Test encryption/decryption
    plaintext = b"Hello, this is a secret message!"
    iv, ciphertext = encrypt_aes_cbc(key, plaintext)
    decrypted = decrypt_aes_cbc(key, iv, ciphertext)
    print(f"Original: {plaintext}")
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()[:32]}...")
    print(f"Decrypted: {decrypted}")
    assert plaintext == decrypted, "Decryption failed!"
    print("✓ AES-128-CBC encryption/decryption working\n")
    
    # Test HMAC
    mac_key = generate_key()
    data = b"Data to authenticate"
    mac = compute_hmac(mac_key, data)
    assert verify_hmac(mac_key, data, mac), "HMAC verification failed!"
    print("✓ HMAC authentication working\n")
    
    # Test key derivation (HKDF)
    master_secret = os.urandom(32)
    salt = os.urandom(16)
    enc_key, mac_key = derive_keys(master_secret, salt)
    print(f"HKDF derived encryption key: {enc_key.hex()} ({len(enc_key)} bytes)")
    print(f"HKDF derived MAC key: {mac_key.hex()[:32]}... ({len(mac_key)} bytes)")
    print("✓ HKDF key derivation working\n")
    
    # Test directional key derivation
    master_key = os.urandom(32)  # Shared master key Ki
    c2s_enc, c2s_mac, s2c_enc, s2c_mac = derive_directional_keys(master_key)
    print(f"Directional Key Derivation from Master Key Ki:")
    print(f"  C2S_Enc_0 = H(Ki || 'C2S-ENC'): {c2s_enc.hex()} ({len(c2s_enc)} bytes)")
    print(f"  C2S_Mac_0 = H(Ki || 'C2S-MAC'): {c2s_mac.hex()[:32]}... ({len(c2s_mac)} bytes)")
    print(f"  S2C_Enc_0 = H(Ki || 'S2C-ENC'): {s2c_enc.hex()} ({len(s2c_enc)} bytes)")
    print(f"  S2C_Mac_0 = H(Ki || 'S2C-MAC'): {s2c_mac.hex()[:32]}... ({len(s2c_mac)} bytes)")
    print("✓ Directional key derivation working\n")
    
    # Test SecureMessage with Encrypt-then-MAC and directional keys
    client_id = 42  # Example client ID (0-255)
    
    # Use directional keys: Client uses C2S keys, Server uses S2C keys
    client_sender = SecureMessage(c2s_enc, c2s_mac, client_id, direction=0)  # Client->Server
    server_receiver = SecureMessage(c2s_enc, c2s_mac, client_id, direction=0)  # Server receives with C2S keys
    
    message = b"This is a secure message with replay protection"
    print(f"Testing Encrypt-then-MAC construction with directional keys:")
    print(f"  1. Plaintext: {message}")
    
    encrypted = client_sender.create_message(message, opcode=30)  # opcode 30 = CLIENT_DATA
    print(f"  2. Client encrypts with C2S keys (PKCS#7, AES-128-CBC, HMAC): {len(encrypted)} bytes")
    
    decrypted_msg, opcode, round_num = server_receiver.parse_message(encrypted)
    print(f"  3. Server decrypts with C2S keys: {decrypted_msg}")
    print(f"     Opcode: {opcode}, Round: {round_num}")
    assert message == decrypted_msg, "Secure message decryption failed!"
    print("✓ SecureMessage with Encrypt-then-MAC and directional keys working\n")
    
    # Test replay protection
    print("Testing replay protection:")
    try:
        server_receiver.parse_message(encrypted)  # Try to replay same message
        print("✗ Replay attack succeeded (BAD!)")
    except CryptoError as e:
        print(f"✓ Replay attack blocked: {e}\n")
    
    # Test tampering detection
    print("Testing tampering detection:")
    tampered = bytearray(encrypted)
    tampered[-10] ^= 0x01  # Flip a bit in the ciphertext
    try:
        server_receiver.parse_message(bytes(tampered))
        print("✗ Tampering not detected (BAD!)")
    except CryptoError as e:
        print(f"✓ Tampering detected: {e}\n")
    
    # Test challenge-response
    challenge = create_challenge()
    shared_secret = os.urandom(32)
    response = create_response(challenge, shared_secret)
    assert verify_response(challenge, response, shared_secret), "Challenge-response failed!"
    print("✓ Challenge-response authentication working\n")
    
    print("All cryptographic tests passed! ✓")
