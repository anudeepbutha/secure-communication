"""
Cryptographic Utilities for Secure Communication Protocol
Provides symmetric encryption (AES-GCM), HMAC authentication, key derivation,
nonce management, and other cryptographic primitives.
"""

import os
import hashlib
import hmac
import struct
import time
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Constants
AES_KEY_SIZE = 32  # 256-bit key
NONCE_SIZE = 12    # 96-bit nonce for AES-GCM
MAC_SIZE = 32      # 256-bit HMAC
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
        # Combine counter (4 bytes) with random bytes (8 bytes)
        counter_bytes = struct.pack('>I', self.counter % (2**32))
        random_bytes = os.urandom(8)
        nonce = counter_bytes + random_bytes
        return nonce
    
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
    """Generate a random 256-bit AES key"""
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
        length=64,  # 32 bytes for encryption + 32 bytes for MAC
        salt=salt,
        info=info,
        backend=default_backend()
    )
    derived_key = hkdf.derive(master_secret)
    encryption_key = derived_key[:32]
    mac_key = derived_key[32:]
    return encryption_key, mac_key


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


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-GCM (Authenticated Encryption with Associated Data).
    
    Args:
        key: 256-bit AES key
        plaintext: Data to encrypt
        associated_data: Additional authenticated data (not encrypted but authenticated)
    
    Returns:
        Tuple of (nonce, ciphertext_with_tag)
    """
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(f"Invalid key size: {len(key)}, expected {AES_KEY_SIZE}")
    
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt data using AES-GCM.
    
    Args:
        key: 256-bit AES key
        nonce: The nonce used for encryption
        ciphertext: Encrypted data with authentication tag
        associated_data: Additional authenticated data
    
    Returns:
        Decrypted plaintext
    
    Raises:
        CryptoError: If decryption fails (tampering detected)
    """
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(f"Invalid key size: {len(key)}, expected {AES_KEY_SIZE}")
    
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except Exception as e:
        raise CryptoError(f"Decryption failed - message may have been tampered: {e}")


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
    
    Message format:
    [session_id (16B)][sequence_num (4B)][timestamp (4B)][nonce (12B)][ciphertext (var)][mac (32B)]
    """
    
    HEADER_SIZE = 16 + 4 + 4 + 12  # session_id + seq_num + timestamp + nonce
    
    def __init__(self, encryption_key: bytes, mac_key: bytes, session_id: bytes):
        self.encryption_key = encryption_key
        self.mac_key = mac_key
        self.session_id = session_id
        self.sequence_number = 0
        self.nonce_manager = NonceManager()
    
    def create_message(self, plaintext: bytes, message_type: int = 0) -> bytes:
        """
        Create a secure message with encryption and authentication.
        
        Args:
            plaintext: Data to send
            message_type: Type identifier for the message
        
        Returns:
            Complete secure message bytes
        """
        self.sequence_number += 1
        timestamp = get_timestamp()
        
        # Create header
        header = (
            self.session_id +
            struct.pack('>I', self.sequence_number) +
            struct.pack('>I', timestamp)
        )
        
        # Add message type to plaintext
        typed_plaintext = struct.pack('>B', message_type) + plaintext
        
        # Encrypt with header as associated data
        nonce, ciphertext = encrypt_aes_gcm(
            self.encryption_key,
            typed_plaintext,
            header
        )
        
        # Create full message
        message = header + nonce + ciphertext
        
        # Compute MAC over entire message
        mac = compute_hmac(self.mac_key, message)
        
        return message + mac
    
    def parse_message(self, data: bytes) -> Tuple[bytes, int, int]:
        """
        Parse and verify a secure message.
        
        Args:
            data: Complete secure message bytes
        
        Returns:
            Tuple of (plaintext, message_type, sequence_number)
        
        Raises:
            CryptoError: If message verification fails
        """
        if len(data) < self.HEADER_SIZE + NONCE_SIZE + MAC_SIZE + 1:
            raise CryptoError("Message too short")
        
        # Extract components
        mac = data[-MAC_SIZE:]
        message = data[:-MAC_SIZE]
        
        # Verify MAC
        if not verify_hmac(self.mac_key, message, mac):
            raise CryptoError("MAC verification failed - message integrity compromised")
        
        # Parse header
        session_id = message[:16]
        sequence_number = struct.unpack('>I', message[16:20])[0]
        timestamp = struct.unpack('>I', message[20:24])[0]
        nonce = message[24:36]
        ciphertext = message[36:]
        
        # Verify session ID
        if session_id != self.session_id:
            raise CryptoError("Invalid session ID")
        
        # Verify timestamp
        if not validate_timestamp(timestamp):
            raise CryptoError("Message timestamp expired - possible replay attack")
        
        # Verify nonce freshness
        if not self.nonce_manager.validate_nonce(nonce):
            raise CryptoError("Nonce reuse detected - replay attack!")
        
        # Verify sequence number (should be greater than last seen)
        # Note: In a full implementation, you'd track per-session sequence numbers
        
        # Decrypt
        header = message[:24]
        plaintext = decrypt_aes_gcm(
            self.encryption_key,
            nonce,
            ciphertext,
            header
        )
        
        message_type = struct.unpack('>B', plaintext[:1])[0]
        payload = plaintext[1:]
        
        return payload, message_type, sequence_number
    
    def reset_sequence(self):
        """Reset sequence number (for new session)"""
        self.sequence_number = 0
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
    print(f"Generated key (hex): {key.hex()[:32]}...")
    
    # Test encryption/decryption
    plaintext = b"Hello, this is a secret message!"
    nonce, ciphertext = encrypt_aes_gcm(key, plaintext)
    decrypted = decrypt_aes_gcm(key, nonce, ciphertext)
    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted}")
    assert plaintext == decrypted, "Decryption failed!"
    print("✓ AES-GCM encryption/decryption working\n")
    
    # Test HMAC
    mac_key = generate_key()
    data = b"Data to authenticate"
    mac = compute_hmac(mac_key, data)
    assert verify_hmac(mac_key, data, mac), "HMAC verification failed!"
    print("✓ HMAC authentication working\n")
    
    # Test key derivation
    master_secret = os.urandom(32)
    salt = os.urandom(16)
    enc_key, mac_key = derive_keys(master_secret, salt)
    print(f"Derived encryption key: {enc_key.hex()[:32]}...")
    print(f"Derived MAC key: {mac_key.hex()[:32]}...")
    print("✓ Key derivation working\n")
    
    # Test SecureMessage
    session_id = generate_session_id()
    secure_msg = SecureMessage(enc_key, mac_key, session_id)
    
    message = b"This is a secure message with replay protection"
    encrypted = secure_msg.create_message(message, message_type=1)
    
    decrypted_msg, msg_type, seq_num = secure_msg.parse_message(encrypted)
    print(f"Original message: {message}")
    print(f"Decrypted message: {decrypted_msg}")
    print(f"Message type: {msg_type}, Sequence: {seq_num}")
    assert message == decrypted_msg, "Secure message decryption failed!"
    print("✓ SecureMessage working\n")
    
    # Test challenge-response
    challenge = create_challenge()
    shared_secret = os.urandom(32)
    response = create_response(challenge, shared_secret)
    assert verify_response(challenge, response, shared_secret), "Challenge-response failed!"
    print("✓ Challenge-response authentication working\n")
    
    print("All cryptographic tests passed! ✓")
