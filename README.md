# Secure Multi-Client Communication with Symmetric Keys
## SNS Lab Assignment 1

### Overview
Implementation of a stateful, symmetric-key-based secure communication protocol between a server and multiple clients in a hostile network environment.

### Features
- ✅ AES-128-CBC encryption with manual PKCS#7 padding
- ✅ HMAC-SHA256 authentication (Encrypt-then-MAC)
- ✅ Directional key derivation and evolution
- ✅ Replay attack protection via round numbers
- ✅ Multi-client support (5 clients with pre-shared keys)
- ✅ Protocol state management via FSM
- ✅ Server-side numeric data aggregation

### Files Structure
```
├── server.py           # Server implementation
├── client.py           # Client implementation
├── crypto_utils.py     # Cryptographic primitives (AES, HMAC, PKCS#7)
├── protocol_fsm.py     # Protocol finite state machine
├── attacks.py          # Attack demonstrations (MITM proxy)
├── README.md           # This file
└── SECURITY.md         # Security analysis
```

### Requirements
```bash
pip install cryptography
```

Python 3.8+

### Pre-Shared Keys (Hardcoded)
```
Client 1: c19b4d0dbb2550550314f0551d829e14
Client 2: fc1288ba000ab08d9bda2cd6eabd15ef
Client 3: a3cc6de5b4d6b6798029f1bb5bbd1e10
Client 4: d91baeccd0d6f5f423c8a4f81cf584a5
Client 5: 1b127762951e5537a14d7a164c166aa0
```

### Quick Start

#### 1. Normal Client-Server Communication

**Terminal 1 - Start Server:**
```bash
python server.py --port 9999 --mode command
```

**Terminal 2 - Start Client:**
```bash
python client.py --id 1 --key c19b4d0dbb2550550314f0551d829e14 --port 9999 -i
> PING
Server: PONG
> TIME
Server: Server time: 2026-01-22T...
> quit
```

#### 2. Aggregation Mode (Multi-Client)

**Terminal 1 - Server:**
```bash
python server.py --port 9999 --mode aggregate
```

**Terminal 2 - Client 1:**
```bash
python client.py --id 1 --key c19b4d0dbb2550550314f0551d829e14 --port 9999 -i
> 10
Server: Round 1 Aggregate: 10.00 (1 clients)
> 20
Server: Round 2 Aggregate: 20.00 (1 clients)
```

**Terminal 3 - Client 2:**
```bash
python client.py --id 2 --key fc1288ba000ab08d9bda2cd6eabd15ef --port 9999 -i
> 15
Server: Round 1 Aggregate: 25.00 (2 clients)
```

**Note**: Per-round aggregation means Round 1 from all clients aggregates together (10 + 15 = 25), Round 2 from all clients aggregates together, etc. Each round maintains its own independent sum across all clients.


#### 3. Attack Demonstrations

**Terminal 1 - Real Server:**
```bash
python server.py --port 9999 --mode command
```

**Terminal 2 - MITM Attacker:**
```bash
python attacks.py --client-port 8888 --server-port 9999
```

**Terminal 3 - Client (connects to attacker):**
```bash
python client.py --id 1 --key c19b4d0dbb2550550314f0551d829e14 --port 8888 -i
```

**Terminal 2 - Select Attack:**
```
Enter Client ID: 1
Select attack type:
  1. Incorrect HMAC
  2. Replay attacks (after session ends)
  3. Message reordering
  4. Key desynchronization
Select: 2
```

### Server Modes

1. **Echo Mode** (`--mode echo`): Echoes back received messages
2. **Command Mode** (`--mode command`): Processes commands (TIME, PING, etc.)
3. **Aggregate Mode** (`--mode aggregate`): Maintains per-round sum across all clients (Round 1 from all clients aggregates together, Round 2 from all clients aggregates together, etc.)

### Protocol Flow

```
1. CLIENT_HELLO (opcode 10)      Client → Server
2. SERVER_CHALLENGE (opcode 20)  Server → Client
3. CLIENT_DATA (opcode 30)       Client → Server
4. SERVER_AGGR_RESPONSE (40)     Server → Client
[Session Established - Data Transfer Phase]
5. Encrypted Data Exchange (opcode 30/40)
6. TERMINATE (opcode 60)         Either → Other
```

### Security Features

#### Key Derivation (Round 0)
```
C2S_Enc_0 = H(Ki || "C2S-ENC")
C2S_Mac_0 = H(Ki || "C2S-MAC")
S2C_Enc_0 = H(Ki || "S2C-ENC")
S2C_Mac_0 = H(Ki || "S2C-MAC")
```

#### Key Evolution (Round R → R+1)
```
Client → Server:
  C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
  C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)

Server → Client:
  S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
  S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
```

#### Message Format
```
[Opcode(1)] [Client_ID(1)] [Round(4)] [Direction(1)] [IV(16)]
[Ciphertext(var)] [HMAC(32)]
```

### Attack Detection

All attacks are detected and result in session termination:
- ✅ **Replay Attack**: HMAC fails (different session keys)
- ✅ **Reordering Attack**: Round number validation + key mismatch
- ✅ **HMAC Tampering**: HMAC verification failure
- ✅ **Key Desync**: HMAC fails (modified header)

### Testing

Run comprehensive tests:
```bash
# Test 1: Normal communication
python server.py --port 9999 --mode command &
python client.py --id 1 --key c19b4d0dbb2550550314f0551d829e14 --port 9999 -i

# Test 2: Multi-client aggregation
python server.py --port 9999 --mode aggregate &
python client.py --id 1 --key c19b4d0dbb2550550314f0551d829e14 --port 9999 -i &
python client.py --id 2 --key fc1288ba000ab08d9bda2cd6eabd15ef --port 9999 -i

# Test 3: Attack scenarios
python server.py --port 9999 --mode command &
python attacks.py --client-port 8888 --server-port 9999 &
python client.py --id 1 --key c19b4d0dbb2550550314f0551d829e14 --port 8888 -i
```

### Known Limitations
- Maximum 5 concurrent clients (hardcoded keys)
- No persistent storage of session state
- No client authentication beyond pre-shared key

### Authors
Group [Your Group Number]

### License
Academic Use Only - SNS Lab Assignment
