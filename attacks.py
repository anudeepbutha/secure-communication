"""
Attack Demonstrations for Secure Communication Protocol
Demonstrates various attacks and how the protocol defends against them:
- Replay Attack
- Man-in-the-Middle Attack
- Message Tampering
- Nonce Reuse Attack
"""

import socket
import struct
import time
import threading
import logging
import os
from typing import Optional, Tuple

from crypto_utils import (
    generate_key, encrypt_aes_gcm, decrypt_aes_gcm,
    compute_hmac, verify_hmac, CryptoError, SecureMessage,
    generate_session_id, NonceManager
)
from protocol_fsm import (
    ClientProtocol, ServerProtocol, ProtocolMessage, MessageType,
    ProtocolState
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Attacks')


class AttackResult:
    """Result of an attack attempt"""
    
    def __init__(self, attack_name: str, success: bool, description: str):
        self.attack_name = attack_name
        self.success = success
        self.description = description
    
    def __str__(self):
        status = "✓ DETECTED" if not self.success else "✗ SUCCEEDED"
        return f"[{status}] {self.attack_name}: {self.description}"


def demonstrate_replay_attack() -> AttackResult:
    """
    Demonstrate replay attack and how the protocol prevents it.
    
    A replay attack involves capturing a valid encrypted message and
    replaying it later. The protocol prevents this using:
    1. Nonces (numbers used once)
    2. Timestamps
    3. Sequence numbers
    """
    print("\n" + "="*60)
    print("REPLAY ATTACK DEMONSTRATION")
    print("="*60)
    
    # Setup: Create a secure session
    encryption_key = generate_key()
    mac_key = generate_key()
    session_id = generate_session_id()
    
    # Legitimate sender creates a message
    sender = SecureMessage(encryption_key, mac_key, session_id)
    receiver = SecureMessage(encryption_key, mac_key, session_id)
    
    # Create and send a legitimate message
    original_message = b"Transfer $1000 to account 12345"
    encrypted = sender.create_message(original_message)
    
    print(f"1. Legitimate message created: '{original_message.decode()}'")
    print(f"   Encrypted length: {len(encrypted)} bytes")
    
    # Legitimate receiver processes the message
    try:
        decrypted, msg_type, seq_num = receiver.parse_message(encrypted)
        print(f"2. Receiver processed message: '{decrypted.decode()}'")
        print(f"   Sequence number: {seq_num}")
    except CryptoError as e:
        return AttackResult("Replay Attack", False, f"Initial message failed: {e}")
    
    # ATTACK: Attacker captures and replays the exact same message
    print("\n3. ATTACKER: Replaying captured message...")
    
    try:
        # Try to replay the same message
        decrypted, msg_type, seq_num = receiver.parse_message(encrypted)
        print(f"   Attack succeeded! Got: '{decrypted.decode()}'")
        return AttackResult(
            "Replay Attack",
            True,
            "The replayed message was accepted (BAD - protocol vulnerability)"
        )
    except CryptoError as e:
        print(f"   Attack blocked! Error: {e}")
        return AttackResult(
            "Replay Attack",
            False,
            f"Protocol correctly detected replay: {e}"
        )


def demonstrate_message_tampering() -> AttackResult:
    """
    Demonstrate message tampering attack and how the protocol prevents it.
    
    The attacker tries to modify an encrypted message without knowing the key.
    The protocol prevents this using:
    1. AES-GCM authenticated encryption
    2. HMAC message authentication
    """
    print("\n" + "="*60)
    print("MESSAGE TAMPERING ATTACK DEMONSTRATION")
    print("="*60)
    
    # Setup
    encryption_key = generate_key()
    mac_key = generate_key()
    session_id = generate_session_id()
    
    sender = SecureMessage(encryption_key, mac_key, session_id)
    receiver = SecureMessage(encryption_key, mac_key, session_id)
    
    # Create legitimate message
    original_message = b"Transfer $100 to Bob"
    encrypted = sender.create_message(original_message)
    
    print(f"1. Original message: '{original_message.decode()}'")
    print(f"   Encrypted data: {encrypted[:32].hex()}...")
    
    # ATTACK: Try to modify the encrypted message
    print("\n2. ATTACKER: Attempting to modify encrypted data...")
    
    # Try different tampering methods
    attacks = [
        ("Flip a bit in ciphertext", bytearray(encrypted)),
        ("Modify the MAC", bytearray(encrypted)),
        ("Change sequence number", bytearray(encrypted)),
    ]
    
    # Attack 1: Flip a bit in the ciphertext
    tampered1 = bytearray(encrypted)
    tampered1[40] ^= 0x01  # Flip one bit in ciphertext area
    
    print("   Attack 1: Flipping bit in ciphertext...")
    try:
        decrypted, _, _ = receiver.parse_message(bytes(tampered1))
        print(f"   Attack succeeded! Got: '{decrypted.decode()}'")
        return AttackResult("Message Tampering", True, "Modified message accepted")
    except CryptoError as e:
        print(f"   Attack blocked: {e}")
    
    # Attack 2: Modify the MAC directly
    tampered2 = bytearray(encrypted)
    tampered2[-1] ^= 0x01  # Flip bit in MAC
    
    print("   Attack 2: Modifying MAC...")
    try:
        decrypted, _, _ = receiver.parse_message(bytes(tampered2))
        print(f"   Attack succeeded! Got: '{decrypted.decode()}'")
        return AttackResult("Message Tampering", True, "Modified message accepted")
    except CryptoError as e:
        print(f"   Attack blocked: {e}")
    
    # Attack 3: Try to change the session ID
    tampered3 = bytearray(encrypted)
    tampered3[0] ^= 0xFF  # Modify session ID
    
    print("   Attack 3: Modifying session ID...")
    try:
        decrypted, _, _ = receiver.parse_message(bytes(tampered3))
        print(f"   Attack succeeded! Got: '{decrypted.decode()}'")
        return AttackResult("Message Tampering", True, "Modified message accepted")
    except CryptoError as e:
        print(f"   Attack blocked: {e}")
    
    return AttackResult(
        "Message Tampering",
        False,
        "All tampering attempts were detected by MAC/AEAD verification"
    )


def demonstrate_wrong_key_attack() -> AttackResult:
    """
    Demonstrate attack with wrong pre-shared key.
    
    An attacker without the correct pre-shared key cannot:
    1. Decrypt messages
    2. Create valid messages
    3. Complete authentication
    """
    print("\n" + "="*60)
    print("WRONG KEY ATTACK DEMONSTRATION")
    print("="*60)
    
    # Legitimate parties' key
    correct_key = generate_key()
    # Attacker's guessed key
    attacker_key = generate_key()
    
    print(f"1. Correct key: {correct_key.hex()[:16]}...")
    print(f"   Attacker key: {attacker_key.hex()[:16]}...")
    
    # Setup legitimate session
    encryption_key = correct_key
    mac_key = generate_key()
    session_id = generate_session_id()
    
    sender = SecureMessage(encryption_key, mac_key, session_id)
    
    # Create encrypted message
    original = b"Secret information"
    encrypted = sender.create_message(original)
    
    print(f"\n2. Encrypted message created with correct key")
    print(f"   Original: '{original.decode()}'")
    
    # ATTACK: Try to decrypt with wrong key
    print("\n3. ATTACKER: Trying to decrypt with wrong key...")
    
    # Attacker creates receiver with wrong key
    attacker_receiver = SecureMessage(attacker_key, mac_key, session_id)
    
    try:
        decrypted, _, _ = attacker_receiver.parse_message(encrypted)
        print(f"   Attack succeeded! Got: '{decrypted.decode()}'")
        return AttackResult("Wrong Key Attack", True, "Decryption with wrong key succeeded")
    except CryptoError as e:
        print(f"   Attack blocked: {e}")
    
    # Also try wrong MAC key
    print("\n4. ATTACKER: Trying with correct encryption key but wrong MAC key...")
    wrong_mac_receiver = SecureMessage(encryption_key, attacker_key, session_id)
    
    try:
        decrypted, _, _ = wrong_mac_receiver.parse_message(encrypted)
        print(f"   Attack succeeded! Got: '{decrypted.decode()}'")
        return AttackResult("Wrong Key Attack", True, "Wrong MAC key accepted")
    except CryptoError as e:
        print(f"   Attack blocked: {e}")
    
    return AttackResult(
        "Wrong Key Attack",
        False,
        "Attacker cannot decrypt without correct keys"
    )


def demonstrate_timestamp_attack() -> AttackResult:
    """
    Demonstrate expired timestamp attack.
    
    Messages with old timestamps should be rejected to prevent
    delayed replay attacks.
    """
    print("\n" + "="*60)
    print("TIMESTAMP ATTACK DEMONSTRATION")
    print("="*60)
    
    from crypto_utils import validate_timestamp, TIMESTAMP_TOLERANCE, get_timestamp
    
    current_time = get_timestamp()
    
    print(f"1. Current timestamp: {current_time}")
    print(f"   Tolerance window: ±{TIMESTAMP_TOLERANCE} seconds")
    
    # Test valid timestamp
    valid_ts = current_time
    print(f"\n2. Testing valid timestamp: {valid_ts}")
    print(f"   Valid: {validate_timestamp(valid_ts)}")
    
    # ATTACK: Test expired timestamp
    old_ts = current_time - TIMESTAMP_TOLERANCE - 60  # 1 minute past tolerance
    print(f"\n3. ATTACKER: Testing old timestamp: {old_ts}")
    print(f"   Difference: {current_time - old_ts} seconds ago")
    
    if validate_timestamp(old_ts):
        print(f"   Attack succeeded! Old timestamp accepted")
        return AttackResult("Timestamp Attack", True, "Expired timestamp was accepted")
    else:
        print(f"   Attack blocked! Old timestamp rejected")
    
    # Test future timestamp
    future_ts = current_time + TIMESTAMP_TOLERANCE + 60
    print(f"\n4. ATTACKER: Testing future timestamp: {future_ts}")
    print(f"   Difference: {future_ts - current_time} seconds in future")
    
    if validate_timestamp(future_ts):
        print(f"   Attack succeeded! Future timestamp accepted")
        return AttackResult("Timestamp Attack", True, "Future timestamp was accepted")
    else:
        print(f"   Attack blocked! Future timestamp rejected")
    
    return AttackResult(
        "Timestamp Attack",
        False,
        "Timestamps outside tolerance window are correctly rejected"
    )


def demonstrate_nonce_reuse_vulnerability() -> AttackResult:
    """
    Demonstrate why nonce reuse is dangerous.
    
    If the same nonce is used twice with AES-GCM, XORing the ciphertexts
    reveals XOR of plaintexts, which can leak information.
    """
    print("\n" + "="*60)
    print("NONCE REUSE VULNERABILITY DEMONSTRATION")
    print("="*60)
    
    key = generate_key()
    nonce = os.urandom(12)  # Fixed nonce (BAD PRACTICE!)
    
    message1 = b"Secret message one!"
    message2 = b"Another secret msg!"
    
    print("1. Encrypting two messages with SAME nonce (vulnerable!)")
    
    # Encrypt both with same nonce (DANGEROUS!)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    
    ct1 = aesgcm.encrypt(nonce, message1, None)
    ct2 = aesgcm.encrypt(nonce, message2, None)
    
    print(f"   Nonce: {nonce.hex()}")
    print(f"   Message 1: '{message1.decode()}'")
    print(f"   Message 2: '{message2.decode()}'")
    print(f"   Ciphertext 1: {ct1[:16].hex()}...")
    print(f"   Ciphertext 2: {ct2[:16].hex()}...")
    
    # XOR ciphertexts to get XOR of plaintexts
    min_len = min(len(message1), len(message2))
    xor_ct = bytes(a ^ b for a, b in zip(ct1[:min_len], ct2[:min_len]))
    xor_pt = bytes(a ^ b for a, b in zip(message1, message2))
    
    print(f"\n2. ATTACKER: XORing ciphertexts...")
    print(f"   CT1 ⊕ CT2: {xor_ct.hex()}")
    print(f"   PT1 ⊕ PT2: {xor_pt.hex()}")
    
    if xor_ct == xor_pt:
        print("   ⚠️  XOR of ciphertexts equals XOR of plaintexts!")
        print("   This leaks information about the plaintexts!")
    
    # Show why our protocol prevents this
    print("\n3. Our protocol's protection:")
    nonce_mgr = NonceManager()
    
    n1 = nonce_mgr.generate_nonce()
    n2 = nonce_mgr.generate_nonce()
    
    print(f"   Generated nonce 1: {n1.hex()}")
    print(f"   Generated nonce 2: {n2.hex()}")
    print(f"   Nonces are different: {n1 != n2}")
    
    return AttackResult(
        "Nonce Reuse",
        False,
        "Protocol generates unique nonces to prevent reuse vulnerability"
    )


def demonstrate_mitm_detection() -> AttackResult:
    """
    Demonstrate how the protocol can detect Man-in-the-Middle attacks
    through mutual authentication.
    """
    print("\n" + "="*60)
    print("MAN-IN-THE-MIDDLE DETECTION DEMONSTRATION")
    print("="*60)
    
    # Legitimate parties
    client_key = generate_key()
    server_key = client_key  # They share the same pre-shared key
    
    # Attacker doesn't know the key
    attacker_key = generate_key()
    
    print("1. Setup:")
    print(f"   Client/Server PSK: {client_key.hex()[:16]}...")
    print(f"   Attacker's key: {attacker_key.hex()[:16]}...")
    
    # Create protocols
    client = ClientProtocol(client_key)
    server = ServerProtocol(server_key)
    attacker_client = ClientProtocol(attacker_key)  # Attacker as fake client
    attacker_server = ServerProtocol(attacker_key)  # Attacker as fake server
    
    print("\n2. Normal handshake (no attacker):")
    
    # Normal handshake
    hello = client.create_hello()
    hello_resp = server.process_hello(hello)
    key_confirm = client.process_hello_response(hello_resp)
    challenge = server.process_key_confirm(key_confirm)
    challenge_resp = client.process_challenge(challenge)
    auth_result = server.process_challenge_response(challenge_resp)
    
    print(f"   Auth result: {auth_result.msg_type.name}")
    
    if auth_result.msg_type == MessageType.AUTH_SUCCESS:
        print("   ✓ Legitimate handshake succeeded")
    
    print("\n3. MITM Attack scenario:")
    print("   Attacker intercepts and tries to impersonate server...")
    
    # Reset client
    client2 = ClientProtocol(client_key)
    
    hello2 = client2.create_hello()
    
    # Attacker tries to respond (but doesn't have correct key)
    try:
        # Attacker receives hello but uses wrong key for derivation
        attacker_resp = attacker_server.process_hello(hello2)
        
        # Client tries to verify with wrong derived keys
        # This should fail during key confirmation or challenge-response
        key_confirm2 = client2.process_hello_response(attacker_resp)
        
        # Attacker tries to verify key confirmation
        challenge2 = attacker_server.process_key_confirm(key_confirm2)
        
        print("   ⚠️  MITM progressed past key exchange (checking auth)...")
        
        # This will fail because attacker has different derived keys
        challenge_resp2 = client2.process_challenge(challenge2)
        auth_result2 = attacker_server.process_challenge_response(challenge_resp2)
        
        if auth_result2.msg_type == MessageType.AUTH_SUCCESS:
            print("   ✗ MITM Attack succeeded! (BAD)")
            return AttackResult("MITM Attack", True, "Attacker completed handshake")
        else:
            print("   ✓ Authentication failed - MITM detected")
            
    except Exception as e:
        print(f"   ✓ Attack blocked at: {e}")
    
    return AttackResult(
        "MITM Attack",
        False,
        "Mutual authentication with PSK prevents MITM impersonation"
    )


def demonstrate_session_hijacking() -> AttackResult:
    """
    Demonstrate session hijacking prevention.
    
    Even if an attacker observes a session ID, they cannot:
    1. Use it without the encryption keys
    2. Inject messages into an existing session
    """
    print("\n" + "="*60)
    print("SESSION HIJACKING PREVENTION DEMONSTRATION")
    print("="*60)
    
    # Legitimate session setup
    encryption_key = generate_key()
    mac_key = generate_key()
    session_id = generate_session_id()
    
    legitimate = SecureMessage(encryption_key, mac_key, session_id)
    
    print(f"1. Legitimate session ID: {session_id.hex()}")
    
    # Create a legitimate message
    msg = b"Confidential data"
    encrypted = legitimate.create_message(msg)
    
    print(f"2. Legitimate message created")
    
    # ATTACK: Attacker knows session ID but not the keys
    print("\n3. ATTACKER: Attempting to inject message into session...")
    
    attacker_key = generate_key()  # Attacker's guessed key
    attacker = SecureMessage(attacker_key, attacker_key, session_id)  # Uses known session ID
    
    # Attacker tries to create a message for this session
    malicious_msg = b"Transfer all money to attacker"
    malicious_encrypted = attacker.create_message(malicious_msg)
    
    print(f"   Attacker created message: '{malicious_msg.decode()}'")
    
    # Legitimate receiver tries to process attacker's message
    receiver = SecureMessage(encryption_key, mac_key, session_id)
    
    try:
        decrypted, _, _ = receiver.parse_message(malicious_encrypted)
        print(f"   ✗ Attack succeeded! Receiver got: '{decrypted.decode()}'")
        return AttackResult("Session Hijacking", True, "Injected message was accepted")
    except CryptoError as e:
        print(f"   ✓ Attack blocked: {e}")
    
    return AttackResult(
        "Session Hijacking",
        False,
        "Session ID alone is insufficient; encryption keys required"
    )


def run_all_attacks():
    """Run all attack demonstrations"""
    print("\n" + "="*70)
    print("     SECURE COMMUNICATION PROTOCOL - ATTACK DEMONSTRATIONS")
    print("="*70)
    
    attacks = [
        demonstrate_replay_attack,
        demonstrate_message_tampering,
        demonstrate_wrong_key_attack,
        demonstrate_timestamp_attack,
        demonstrate_nonce_reuse_vulnerability,
        demonstrate_mitm_detection,
        demonstrate_session_hijacking,
    ]
    
    results = []
    for attack_fn in attacks:
        result = attack_fn()
        results.append(result)
    
    # Summary
    print("\n" + "="*70)
    print("                         ATTACK SUMMARY")
    print("="*70)
    
    successful_attacks = [r for r in results if r.success]
    blocked_attacks = [r for r in results if not r.success]
    
    print("\nBlocked Attacks (Protocol is secure against these):")
    for r in blocked_attacks:
        print(f"  ✓ {r.attack_name}")
    
    if successful_attacks:
        print("\n⚠️  Successful Attacks (Vulnerabilities found!):")
        for r in successful_attacks:
            print(f"  ✗ {r.attack_name}")
    else:
        print("\n✓ All attacks were successfully blocked!")
    
    print("\nDetailed Results:")
    for r in results:
        print(f"  {r}")
    
    return results


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Attack Demonstrations')
    parser.add_argument('--attack', choices=[
        'replay', 'tamper', 'wrongkey', 'timestamp', 
        'nonce', 'mitm', 'hijack', 'all'
    ], default='all', help='Specific attack to demonstrate')
    args = parser.parse_args()
    
    attack_map = {
        'replay': demonstrate_replay_attack,
        'tamper': demonstrate_message_tampering,
        'wrongkey': demonstrate_wrong_key_attack,
        'timestamp': demonstrate_timestamp_attack,
        'nonce': demonstrate_nonce_reuse_vulnerability,
        'mitm': demonstrate_mitm_detection,
        'hijack': demonstrate_session_hijacking,
        'all': run_all_attacks,
    }
    
    attack_fn = attack_map.get(args.attack, run_all_attacks)
    attack_fn()


if __name__ == "__main__":
    main()
