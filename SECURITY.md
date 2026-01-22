# Security Analysis
## Protocol Design and Attack Mitigation

### 1. Threat Model

#### Assumptions
- **Active Network Adversary**: Can intercept, modify, drop, replay, and reorder messages
- **Cryptographic Primitives**: AES-128 and HMAC-SHA256 are secure
- **Pre-Shared Keys**: Securely distributed out-of-band before protocol starts
- **No PKI**: Public-key cryptography unavailable

#### Out of Scope
- Side-channel attacks (timing, power analysis)
- Denial of Service (DoS)
- Physical security of endpoints
- Social engineering

---

### 2. Security Properties

#### 2.1 Confidentiality 

**Mechanism**: AES-128-CBC Encryption

**How it works**:
- All data encrypted with AES-128-CBC
- Fresh random IV generated for each message
- Directional keys ensure separate encryption for each direction

**Why it's secure**:
- AES-128 provides 2^128 computational security
- CBC mode with random IVs prevents pattern analysis
- No IV reuse within same session

**Attack Resistance**:
-  **Eavesdropping**: Ciphertext reveals no plaintext information
-  **Pattern Analysis**: Random IVs prevent identical plaintexts from producing identical ciphertexts

---

#### 2.2 Integrity 

**Mechanism**: HMAC-SHA256 (Encrypt-then-MAC)

**How it works**:
```
Message = Header || Ciphertext || HMAC
HMAC = HMAC-SHA256(Mac_Key, Header || Ciphertext)
```

**Critical Design Decision**: Verify HMAC BEFORE decryption

```python
# Receiver-side verification order:
1. Verify HMAC  ← Must be first!
2. If HMAC fails → Terminate session immediately
3. If HMAC passes → Decrypt ciphertext
4. Remove padding
```

**Why Encrypt-then-MAC**:
- MAC covers ciphertext, so tampering detected before decryption
- Prevents padding oracle attacks
- Prevents chosen-ciphertext attacks

**Attack Resistance**:
-  **Tampering**: Any bit flip → HMAC verification fails → Session terminates
-  **Padding Oracle**: Decryption only occurs after HMAC verification

---

#### 2.3 Freshness (Replay Protection) 

**Mechanism**: Round Number Tracking + Key Evolution

**How it works**:
```python
# Sender side:
round_number += 1  # Increment for each message
message = create_message(data, round_number)

# Receiver side:
if received_round <= last_received_round:
    raise CryptoError("Replay or reorder attack")
last_received_round = received_round
```

**Key Evolution Prevents Replay**:
```
Round 1: Keys K1_enc, K1_mac
  → Evolve after message
Round 2: Keys K2_enc, K2_mac
  → Evolve after message
Round 3: Keys K3_enc, K3_mac

Old message from Round 1:
  - Has HMAC computed with K1_mac
  - Current session uses K3_mac
  - HMAC verification FAILS
```

**Attack Resistance**:
-  **Replay Attack**: Old messages have HMACs with old keys → HMAC fails
-  **Reflection Attack**: Direction bit prevents reflecting C→S as S→C

**Demonstration**:
```
Session 1:
  Client sends: "PING" with Round 1, HMAC(K1_mac)
  [Session completes, keys evolved to K5]

Session 2:
  Attacker replays: "PING" with Round 1, HMAC(K1_mac)
  Server verifies: HMAC using current key K1_mac (different from old K1_mac)
  Result: HMAC FAILS → Session terminated
```

---

#### 2.4 Ordering (Reorder Protection) 

**Mechanism**: Strict Round Number Sequencing

**How it works**:
```python
# Messages must arrive in strict sequence
Expected: Round 1, 2, 3, 4, 5, ...
Received: Round 1, 3, 2, 4 → REJECT at Round 3

if round_number != last_received_round + 1:
    # For strict validation (optional enhancement)
    raise Error("Out of order")

# Current implementation (also secure):
if round_number <= last_received_round:
    raise Error("Replay or reorder")
```

**Why Key Evolution Prevents Reordering**:
```
Normal flow:
  Round 1 → Keys evolve → Round 2 → Keys evolve → Round 3

Reordering attack: Round 1 → [hold 2] → Round 3 → Round 2
  Server expects Round 2, receives Round 3
  Server evolved keys for Round 2
  Round 3 message encrypted with Round 3 keys
  → Key mismatch → HMAC fails
```

**Attack Resistance**:
-  **Message Reordering**: Round check + key evolution prevents out-of-order messages

**Demonstration**:
```
Attacker intercepts:
  msg1 (Round 1), msg2 (Round 2), msg3 (Round 3)

Attacker reorders: msg1 → [hold msg2] → msg3 → msg2

Server processing:
   msg1 (Round 1): Expected 1, got 1 → Accept
  ✗ msg3 (Round 3): Expected 2, got 3 → Reject OR HMAC fails
```

---

#### 2.5 Key Desynchronization Prevention 

**Mechanism**: Atomic Key Evolution

**How it works**:
```python
# Key evolution happens ONLY after successful verification
def parse_message(data):
    verify_hmac(data)  # Step 1: Verify
    decrypt(data)      # Step 2: Decrypt
    evolve_keys()      # Step 3: Evolve ONLY if steps 1-2 succeed

# If ANY step fails:
    terminate_session()  # Keys NOT evolved
```

**Why This Prevents Desynchronization**:
- If attacker modifies round number → HMAC fails → Keys not evolved
- If attacker replays old message → HMAC fails → Keys not evolved
- Sender and receiver evolve keys in lockstep

**Attack Resistance**:
-  **Desync Attack**: Modifying round number → HMAC fails before key evolution

**Demonstration**:
```
Attacker modifies Round 2 → Round 12:
  Header: [Opcode][Client_ID][Round=12][Direction][IV]
  HMAC covers header, so modifying Round affects HMAC
  Server: verify_hmac() → FAILS
  Server: Keys NOT evolved, session terminated
```

---

### 3. Attack Demonstrations

#### 3.1 Replay Attack  BLOCKED

**Attack Scenario**:
```
1. Attacker captures messages from Client 1's session
2. Client 1 disconnects (session ends)
3. Attacker creates new connection
4. Attacker replays captured messages
```

**Detection Mechanism**:
- Different sessions have independently evolved keys
- Old messages encrypted with old session keys
- HMAC verification fails

**Test Result**:  Session terminated, no data leakage

---

#### 3.2 Message Reordering  BLOCKED

**Attack Scenario**:
```
Attacker intercepts:
  msg1 (Round 1), msg2 (Round 2), msg3 (Round 3)

Attacker sends:
  msg1 → [hold msg2] → msg3 → msg2
```

**Detection Mechanism**:
- Server expects Round 2, receives Round 3
- Keys evolved for Round 2, message uses Round 3 keys
- HMAC verification fails OR round number check fails

**Test Result**:  Session terminated at msg3

---

#### 3.3 HMAC Tampering  BLOCKED

**Attack Scenario**:
```
Attacker flips 1 bit in ciphertext
```

**Detection Mechanism**:
- HMAC covers entire message (header + ciphertext)
- Any modification → HMAC verification fails
- Session terminated BEFORE decryption

**Test Result**:  Tampering detected, session terminated

---

#### 3.4 Key Desynchronization  BLOCKED

**Attack Scenario**:
```
Attacker modifies round number in header
```

**Detection Mechanism**:
- Round number is part of header
- HMAC covers header
- Modifying round → HMAC fails

**Test Result**:  Modification detected, session terminated

---

### 4. Key Management

#### 4.1 Key Hierarchy

```
Master Key Ki (Pre-shared, 128-bit)
    ↓
Directional Keys (Round 0):
    - C2S_Enc_0 = H(Ki || "C2S-ENC")
    - C2S_Mac_0 = H(Ki || "C2S-MAC")
    - S2C_Enc_0 = H(Ki || "S2C-ENC")
    - S2C_Mac_0 = H(Ki || "S2C-MAC")
    ↓
Evolved Keys (Round R+1):
    - C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
    - C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
    - S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
    - S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
```

#### 4.2 Forward Secrecy (Limited)

**Property**: Compromising Round R keys doesn't reveal Round R-1 data

**Why**: Hash functions are one-way
```
K_R+1 = H(K_R || data)
Given K_R+1, cannot compute K_R (hash preimage resistance)
```

**Limitation**: No backward secrecy
```
Given K_R, can compute K_R+1, K_R+2, ... (forward computation)
```

**Mitigation**: Session termination on any attack prevents forward computation

---

### 5. Cryptographic Choices

#### 5.1 AES-128-CBC

**Choice Rationale**:
- Industry standard block cipher
- 128-bit key sufficient for symmetric encryption
- CBC mode widely understood and analyzed
- Manual IV generation provides explicit control

**Security Considerations**:
-  Random IV for each message prevents pattern analysis
-  No IV reuse within session
-  Padding oracle attacks mitigated by Encrypt-then-MAC
-  CBC mode requires careful padding (PKCS#7 manually implemented)

#### 5.2 HMAC-SHA256

**Choice Rationale**:
- Provides 256-bit security for authentication
- Resistant to length extension attacks
- Standardized in RFC 2104

**Security Considerations**:
-  Separate MAC keys for each direction
-  MAC covers entire message (header + ciphertext)
-  Constant-time comparison prevents timing attacks

#### 5.3 PKCS#7 Padding

**Manual Implementation Required**:
```python
def pkcs7_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(padded_data, block_size=16):
    padding_length = padded_data[-1]
    # Validate all padding bytes
    for i in range(padding_length):
        if padded_data[-(i+1)] != padding_length:
            raise CryptoError("Invalid PKCS#7 padding")
    return padded_data[:-padding_length]
```

**Security Considerations**:
-  Padding always applied (even if data is block-aligned)
-  Validation prevents padding oracle attacks
-  Padding errors treated as authentication failures

---

### 6. Protocol State Management

#### 6.1 Finite State Machine

```
Client States:
INIT → HELLO_SENT → CHALLENGE_RECEIVED → DATA_SENT → ESTABLISHED → DATA_TRANSFER → CLOSING → CLOSED

Server States:
INIT → HELLO_RECEIVED → CHALLENGE_SENT → ESTABLISHED → DATA_TRANSFER → CLOSING → CLOSED

Error State (both):
ANY_STATE → ERROR → CLOSED (on attack detection)
```

#### 6.2 State Transition Security

**Invalid transitions rejected**:
```python
if new_state not in valid_transitions[current_state]:
    raise StateTransitionError("Invalid transition")
```

**Attack Resistance**:
-  **Protocol Confusion**: Out-of-order opcodes rejected
-  **State Desync**: Both parties must be in compatible states

---

### 7. Multi-Client Security

#### 7.1 Client Isolation

**Property**: Each client session is cryptographically isolated

**Mechanism**:
- Separate master keys for each client
- Independent key evolution per session
- No key material shared between clients

**Security Guarantee**:
```
Compromising Client 1's keys does NOT affect Client 2's security
```

#### 7.2 Aggregation Security

**Design**:
- Server maintains global aggregate
- Each client receives aggregate encrypted with their own keys
- No client can decrypt another client's communications

**Privacy Consideration**:
-  Aggregate value reveals sum, not individual contributions
-  With 2 clients, Client 2 can infer Client 1's value
-  With many clients, individual privacy improved

---

### 8. Implementation Security

#### 8.1 Error Handling

**Critical Rule**: Fail securely
```python
try:
    verify_hmac()
    decrypt()
    process()
except CryptoError:
    # Terminate session, don't reveal error details
    send_error_and_close()
```

**Attack Resistance**:
-  No information leakage through error messages
-  Consistent error handling for all attacks

#### 8.2 Constant-Time Operations

**HMAC Verification**:
```python
def verify_hmac(key, data, expected_mac):
    computed_mac = compute_hmac(key, data)
    return hmac.compare_digest(computed_mac, expected_mac)  # Constant-time
```

**Why**: Prevents timing side-channels

#### 8.3 Random Number Generation

**Source**: OS-level cryptographically secure RNG
```python
iv = os.urandom(16)  # Uses /dev/urandom on Unix
```

**Security**: Provides unpredictable IVs and nonces

---

### 9. Known Limitations

#### 9.1 No Forward Secrecy (Full)

**Issue**: Compromising current round keys allows computing future keys

**Mitigation**: Session-based (new session = new key derivation)

#### 9.2 No Backward Secrecy

**Issue**: Cannot compute past keys from current keys

**Not a Problem**: Past data already transmitted securely

#### 9.3 No Authentication of Initial Key

**Assumption**: Pre-shared keys distributed securely out-of-band

**Risk**: If key compromised before protocol start, attacker can impersonate

#### 9.4 Denial of Service

**Out of Scope**: Protocol doesn't prevent DoS attacks

**Examples**:
- Flooding server with connections
- Sending invalid messages to consume resources

---

### 10. Comparison with Standard Protocols

#### vs. TLS 1.3

| Feature | This Protocol | TLS 1.3 |
|---------|--------------|---------|
| Key Exchange | Pre-shared | ECDHE (forward secrecy) |
| Encryption | AES-128-CBC | AES-GCM (AEAD) |
| Authentication | HMAC | Integrated (AEAD) |
| Handshake | 4 messages | 1-RTT or 0-RTT |
| Perfect Forward Secrecy | No | Yes |
| Complexity | Low | High |

**Advantage**: Simpler, no PKI required
**Disadvantage**: No PFS, weaker than modern TLS

#### vs. Signal Protocol

| Feature | This Protocol | Signal |
|---------|--------------|--------|
| Key Agreement | Pre-shared | X3DH |
| Ratcheting | Per-round hash | Double Ratchet |
| Forward Secrecy | Limited | Full (DH ratchet) |
| Asynchronous | No | Yes |

**Advantage**: Simpler implementation
**Disadvantage**: No full forward secrecy

---

### 11. Security Audit Checklist

- [x] Encrypt-then-MAC construction
- [x] HMAC verified BEFORE decryption
- [x] No automatic padding (manual PKCS#7)
- [x] Random IV for each message
- [x] No IV reuse
- [x] Constant-time HMAC comparison
- [x] Directional keys (C2S ≠ S2C)
- [x] Key evolution after successful verification
- [x] Round number validation
- [x] Session termination on any attack
- [x] No error information leakage
- [x] Cryptographically secure RNG
- [x] State transition validation
- [x] Multi-client isolation

---

### 12. Conclusion

**Security Summary**:
- ✅ **Confidentiality**: AES-128-CBC with random IVs
- ✅ **Integrity**: HMAC-SHA256 (Encrypt-then-MAC)
- ✅ **Freshness**: Round numbers + key evolution
- ✅ **Ordering**: Strict round sequencing
- ✅ **Attack Resistance**: All mandatory attacks blocked

**Threat Model Coverage**:
- ✅ Replay attacks: Blocked by key evolution
- ✅ Message reordering: Blocked by round validation + key mismatch
- ✅ Tampering: Blocked by HMAC verification
- ✅ Key desynchronization: Blocked by atomic evolution

**Suitable For**:
- Constrained environments without PKI
- Known participants with pre-shared keys
- Applications requiring simple symmetric crypto

**Not Suitable For**:
- Public internet (use TLS instead)
- Long-term key compromise scenarios (no PFS)
- Applications requiring perfect forward secrecy

---

**Document Version**: 1.0  
**Last Updated**: 2026-01-22  
**Authors**: Group [Your Group Number]
