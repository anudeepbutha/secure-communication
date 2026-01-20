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


def demonstrate_packet_drop_reorder() -> AttackResult:
    """
    Demonstrate packet drop and reorder attack.
    
    Attack 3: Drop or reorder packets
    The attacker drops messages or delivers them out of order.
    The protocol detects this using sequence numbers.
    """
    print("\n" + "="*60)
    print("PACKET DROP/REORDER ATTACK DEMONSTRATION")
    print("="*60)
    
    # Setup: Create a secure session
    encryption_key = generate_key()
    mac_key = generate_key()
    session_id = generate_session_id()
    
    sender = SecureMessage(encryption_key, mac_key, session_id)
    receiver = SecureMessage(encryption_key, mac_key, session_id)
    
    # Create a sequence of messages
    messages = [
        b"Message 1",
        b"Message 2",
        b"Message 3",
        b"Message 4"
    ]
    
    encrypted_msgs = [sender.create_message(msg) for msg in messages]
    
    print("1. Legitimate sequence created:")
    for i, msg in enumerate(messages, 1):
        print(f"   Message {i}: '{msg.decode()}'")
    
    # Process messages in order (should work)
    print("\n2. Processing messages in correct order:")
    for i, enc_msg in enumerate(encrypted_msgs, 1):
        try:
            decrypted, _, seq = receiver.parse_message(enc_msg)
            print(f"   ✓ Message {i} accepted (seq={seq}): '{decrypted.decode()}'")
        except CryptoError as e:
            print(f"   ✗ Message {i} rejected: {e}")
            return AttackResult("Packet Drop/Reorder", True, "Valid message rejected")
    
    # ATTACK 1: Try to replay message 2 (drop and replay)
    print("\n3. ATTACKER: Replaying Message 2 (already processed)...")
    try:
        decrypted, _, seq = receiver.parse_message(encrypted_msgs[1])
        print(f"   ✗ Attack succeeded! Replay accepted: '{decrypted.decode()}'")
        return AttackResult("Packet Drop/Reorder", True, "Replay attack succeeded")
    except CryptoError as e:
        print(f"   ✓ Attack blocked: {e}")
    
    # ATTACK 2: Create new session and deliver messages out of order
    print("\n4. ATTACKER: Delivering messages out of order...")
    sender2 = SecureMessage(encryption_key, mac_key, generate_session_id())
    receiver2 = SecureMessage(encryption_key, mac_key, sender2.session_id)
    
    msg_a = sender2.create_message(b"First message")
    msg_b = sender2.create_message(b"Second message")
    msg_c = sender2.create_message(b"Third message")
    
    print("   Normal order: First -> Second -> Third")
    print("   Attacker delivers: Second -> First -> Third (reordered)")
    
    # Try to deliver second message first
    try:
        # Process first message normally
        decrypted, _, _ = receiver2.parse_message(msg_a)
        print(f"   ✓ First message accepted: '{decrypted.decode()}'")
        
        # Attacker tries to deliver third before second
        decrypted, _, _ = receiver2.parse_message(msg_c)
        print(f"   ✗ Third message accepted out of order: '{decrypted.decode()}'")
        return AttackResult("Packet Drop/Reorder", True, "Out-of-order delivery accepted")
    except CryptoError as e:
        print(f"   ✓ Out-of-order delivery blocked: {e}")
    
    return AttackResult(
        "Packet Drop/Reorder",
        False,
        "Sequence numbers prevent replay and reordering attacks"
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


def demonstrate_packet_drop_reorder() -> AttackResult:
    """
    Demonstrate packet drop and reorder attack.
    
    Attack 3: Drop or reorder packets
    The attacker drops messages or delivers them out of order.
    The protocol detects this using sequence numbers.
    """
    print("\n" + "="*60)
    print("PACKET DROP/REORDER ATTACK DEMONSTRATION")
    print("="*60)
    
    # Setup: Create a secure session
    encryption_key = generate_key()
    mac_key = generate_key()
    session_id = generate_session_id()
    
    sender = SecureMessage(encryption_key, mac_key, session_id)
    receiver = SecureMessage(encryption_key, mac_key, session_id)
    
    # Create a sequence of messages
    messages = [
        b"Message 1",
        b"Message 2",
        b"Message 3",
        b"Message 4"
    ]
    
    encrypted_msgs = [sender.create_message(msg) for msg in messages]
    
    print("1. Legitimate sequence created:")
    for i, msg in enumerate(messages, 1):
        print(f"   Message {i}: '{msg.decode()}'")
    
    # Process messages in order (should work)
    print("\n2. Processing messages in correct order:")
    for i, enc_msg in enumerate(encrypted_msgs, 1):
        try:
            decrypted, _, seq = receiver.parse_message(enc_msg)
            print(f"   ✓ Message {i} accepted (seq={seq}): '{decrypted.decode()}'")
        except CryptoError as e:
            print(f"   ✗ Message {i} rejected: {e}")
            return AttackResult("Packet Drop/Reorder", True, "Valid message rejected")
    
    # ATTACK 1: Try to replay message 2 (drop and replay)
    print("\n3. ATTACKER: Replaying Message 2 (already processed)...")
    try:
        decrypted, _, seq = receiver.parse_message(encrypted_msgs[1])
        print(f"   ✗ Attack succeeded! Replay accepted: '{decrypted.decode()}'")
        return AttackResult("Packet Drop/Reorder", True, "Replay attack succeeded")
    except CryptoError as e:
        print(f"   ✓ Attack blocked: {e}")
    
    # ATTACK 2: Create new session and deliver messages out of order
    print("\n4. ATTACKER: Delivering messages out of order...")
    sender2 = SecureMessage(encryption_key, mac_key, generate_session_id())
    receiver2 = SecureMessage(encryption_key, mac_key, sender2.session_id)
    
    msg_a = sender2.create_message(b"First message")
    msg_b = sender2.create_message(b"Second message")
    msg_c = sender2.create_message(b"Third message")
    
    print("   Normal order: First -> Second -> Third")
    print("   Attacker delivers: First -> Third -> Second (reordered)")
    
    # Try to deliver messages out of order
    try:
        # Process first message normally
        decrypted, _, _ = receiver2.parse_message(msg_a)
        print(f"   ✓ First message accepted: '{decrypted.decode()}'")
        
        # Attacker tries to deliver third before second
        decrypted, _, _ = receiver2.parse_message(msg_c)
        print(f"   ✗ Third message accepted out of order: '{decrypted.decode()}'")
        return AttackResult("Packet Drop/Reorder", True, "Out-of-order delivery accepted")
    except CryptoError as e:
        print(f"   ✓ Out-of-order delivery blocked: {e}")
    
    return AttackResult(
        "Packet Drop/Reorder",
        False,
        "Sequence numbers prevent replay and reordering attacks"
    )


def demonstrate_reflection_attack() -> AttackResult:
    """
    Demonstrate reflection attack.
    
    Attack 4: Reflect messages back to the sender
    The attacker captures a message from Alice to Bob and sends it back to Alice,
    pretending it came from Bob. The protocol detects this using session IDs.
    """
    print("\n" + "="*60)
    print("REFLECTION ATTACK DEMONSTRATION")
    print("="*60)
    
    # Setup: Two different sessions (Alice->Bob and Bob->Alice)
    encryption_key = generate_key()
    mac_key = generate_key()
    
    alice_session = generate_session_id()
    bob_session = generate_session_id()
    
    alice_to_bob = SecureMessage(encryption_key, mac_key, alice_session)
    bob_to_alice = SecureMessage(encryption_key, mac_key, bob_session)
    
    print(f"1. Setup two sessions:")
    print(f"   Alice's session: {alice_session.hex()[:16]}...")
    print(f"   Bob's session:   {bob_session.hex()[:16]}...")
    
    # Alice sends a message to Bob
    alice_message = b"Transfer $1000 to Bob"
    encrypted = alice_to_bob.create_message(alice_message)
    
    print(f"\n2. Alice sends to Bob: '{alice_message.decode()}'")
    
    # ATTACK: Attacker reflects the message back to Alice
    print("\n3. ATTACKER: Reflecting Alice's message back to her...")
    print("   Pretending the message is from Bob to Alice")
    
    # Alice's receiver expects messages with Alice's session ID
    alice_receiver = SecureMessage(encryption_key, mac_key, alice_session)
    
    try:
        # Try to process Alice's own message
        decrypted, _, _ = alice_receiver.parse_message(encrypted)
        print(f"   ✗ Reflection succeeded! Alice processed: '{decrypted.decode()}'")
        return AttackResult("Reflection Attack", True, "Reflected message was accepted")
    except CryptoError as e:
        print(f"   ✓ Reflection blocked: {e}")
    
    # Show how session IDs prevent this
    print("\n4. Why it failed:")
    print(f"   Alice's message has session ID: {alice_session.hex()[:16]}")
    print(f"   Alice expects to receive with session ID: {alice_session.hex()[:16]}")
    print("   Session IDs in both directions should be different!")
    
    # Demonstrate correct usage with different session IDs
    print("\n5. Correct protocol: Different session IDs per direction")
    alice_sends = SecureMessage(encryption_key, mac_key, alice_session)
    alice_receives = SecureMessage(encryption_key, mac_key, bob_session)
    
    msg_to_bob = alice_sends.create_message(b"Hello Bob")
    print(f"   Alice sends with session: {alice_session.hex()[:16]}...")
    
    # Bob receives with Alice's session ID
    bob_receives = SecureMessage(encryption_key, mac_key, alice_session)
    decrypted, _, _ = bob_receives.parse_message(msg_to_bob)
    print(f"   Bob receives: '{decrypted.decode()}'")
    
    # Bob responds with his session ID
    bob_sends = SecureMessage(encryption_key, mac_key, bob_session)
    msg_to_alice = bob_sends.create_message(b"Hello Alice")
    print(f"   Bob responds with session: {bob_session.hex()[:16]}...")
    
    # Alice receives with Bob's session ID
    decrypted, _, _ = alice_receives.parse_message(msg_to_alice)
    print(f"   Alice receives: '{decrypted.decode()}'")
    print("   ✓ Different session IDs prevent reflection")
    
    return AttackResult(
        "Reflection Attack",
        False,
        "Session ID binding prevents reflection attacks"
    )


def run_all_attacks():
    """Run all attack demonstrations"""
    print("\n" + "="*70)
    print("     SECURE COMMUNICATION PROTOCOL - ATTACK DEMONSTRATIONS")
    print("="*70)
    
    attacks = [
        demonstrate_replay_attack,
        demonstrate_message_tampering,
        demonstrate_packet_drop_reorder,
        demonstrate_reflection_attack,
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
        print("\nSuccessful Attacks (Vulnerabilities found!):")
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
        'replay', 'tamper', 'reorder', 'reflect', 'all'
    ], default='all', help='Specific attack to demonstrate')
    args = parser.parse_args()
    
    attack_map = {
        'replay': demonstrate_replay_attack,
        'tamper': demonstrate_message_tampering,
        'reorder': demonstrate_packet_drop_reorder,
        'reflect': demonstrate_reflection_attack,
        'all': run_all_attacks,
    }
    
    attack_fn = attack_map.get(args.attack, run_all_attacks)
    attack_fn()


if __name__ == "__main__":
    main()
