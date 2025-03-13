# TetraCryptPGC Protocol Specification

## 1. Introduction
TetraCryptPGC is a mutually authenticated key exchange protocol designed to provide post-quantum security. It integrates the Kyber-1024 Key Encapsulation Mechanism (KEM) for shared secret establishment and the Falcon-1024 digital signature scheme for mutual authentication. This document specifies the TetraPQ-XDH handshake protocol, detailing its components, operational steps, and security properties.

## 2. Notation
- `←`: Assignment or sampling.
- `Kyber.KeyGen()`, `Kyber.Encapsulate(pk)`, `Kyber.Decapsulate(ct, sk)`: Kyber-1024 functions.
- `Falcon.KeyGen()`, `Falcon.Sign(m, sk)`, `Falcon.Verify(m, sig, pk)`: Falcon-1024 functions.
- `A || B`: Concatenation of byte strings A and B.
- `H(m)`: A cryptographic hash function (e.g., SHA-256), if used.

## 3. Protocol Components
### 3.1 Kyber-1024 KEM
- **Parameter Set**: As defined in the CRYSTALS-Kyber specification (Round 3).
- **Functions**:
  - `Kyber.KeyGen() → (pk, sk)`: Generates a public-private key pair.
  - `Kyber.Encapsulate(pk) → (ct, ss)`: Generates a ciphertext `ct` and shared secret `ss`.
  - `Kyber.Decapsulate(ct, sk) → ss`: Recovers the shared secret `ss` from `ct`.
- **Security**: IND-CCA2 under the Module Learning With Errors (MLWE) assumption.

### 3.2 Falcon-1024 Signature Scheme
- **Parameter Set**: As defined in the Falcon specification (Round 3).
- **Functions**:
  - `Falcon.KeyGen() → (pk, sk)`: Generates a public-private key pair.
  - `Falcon.Sign(m, sk) → sig`: Signs message `m` with private key `sk`.
  - `Falcon.Verify(m, sig, pk) → {True, False}`: Verifies the signature `sig` on `m` with `pk`.
- **Security**: EUF-CMA under the Short Integer Solution (SIS) assumption.

## 4. TetraPQ-XDH Handshake Protocol

### 4.1 Overview
The TetraPQ-XDH (TetraCrypt Post-Quantum Extended Diffie-Hellman) protocol is a cryptographic handshake designed to establish a shared secret between two parties, Alice and Bob, with mutual authentication in a post-quantum secure manner. It leverages Kyber-1024 for a single-round key encapsulation to derive a shared secret and Falcon-1024 for digital signatures to authenticate both parties. This hybrid approach ensures that the protocol achieves confidentiality, integrity, authenticity, and forward secrecy, making it suitable for applications requiring robust post-quantum security.

### 4.2 Protocol Steps
**Inputs**: None (all key material is generated internally).  
**Outputs**:
- Shared secret `ss` (32 bytes, identical for both parties if successful).
- Authentication status `valid` (boolean, indicating mutual authentication success).

#### Step 1: Key Pair Generation
- **Alice** and **Bob** each generate:
  - **Kyber-1024 key pair**: `(pk_kyber, sk_kyber) ← Kyber.KeyGen()`
  - **Falcon-1024 key pair**: `(pk_falcon, sk_falcon) ← Falcon.KeyGen()`

#### Step 2: Key Exchange Initiation
- **Bob encapsulates** a shared secret using Alice’s Kyber public key:  
  `(ct, ss) ← Kyber.Encapsulate(pk_A_kyber)`
- **Bob transmits** `(ct, pk_B_kyber, pk_B_falcon)` to Alice.

#### Step 3: Key Exchange Completion
- **Alice decapsulates** the shared secret:  
  `ss_A ← Kyber.Decapsulate(ct, sk_A_kyber)`
- **Alice transmits** `(pk_A_kyber, pk_A_falcon)` to Bob (if not pre-shared).

#### Step 4: Mutual Authentication
- **Both Alice and Bob sign** the shared secret with Falcon-1024:
  - `sig_A ← Falcon.Sign(ss_A, sk_A_falcon)`  
  - `sig_B ← Falcon.Sign(ss_B, sk_B_falcon)`
- **Both parties exchange and verify** signatures using each other’s Falcon public keys.

#### Step 5: Verification
- **Alice verifies** Bob’s signature:  
  `valid_B ← Falcon.Verify(ss_A, sig_B, pk_B_falcon)`
- **Bob verifies** Alice’s signature:  
  `valid_A ← Falcon.Verify(ss_B, sig_A, pk_A_falcon)`

### 4.3 Security Properties
- **Confidentiality**: Kyber-1024 ensures shared secret secrecy under MLWE.
- **Integrity**: Falcon-1024 prevents unauthorized message modification.
- **Mutual Authentication**: Falcon signatures confirm each party’s identity.
- **Forward Secrecy**: Ephemeral Kyber keys ensure past session security.

### 4.4 Communication Overhead
- **Total Messages**: 2 (assuming pre-shared public keys are optional).
- **Total Bandwidth**: ~10 KB for a full exchange.

## 5. Parameter Selection
- **Kyber-1024**: Chosen for its IND-CCA2 security (Category 5).
- **Falcon-1024**: Provides EUF-CMA security under SIS.
- **Shared Secret Size**: 32 bytes (256 bits).
- **Alternative Parameters**: Lower security options (Kyber-512, Falcon-512) rejected.

## 6. References

### 6.1 Primary Sources
- **CRYSTALS-Kyber Specification** (NIST PQC Round 3)
- **Falcon Specification** (NIST PQC Round 3)

### 6.2 Supporting References
- **PQCLEAN Project**: https://github.com/PQClean/PQClean
- **NIST PQC Standardization**: https://csrc.nist.gov/projects/post-quantum-cryptography

### 6.3 Additional Reading
- **Lattice Cryptography**: Chris Peikert (MLWE & SIS problems overview).
- **Key Exchange Protocols**: RFC 7748 (Elliptic Curves, XDH inspiration).

### 6.4 Implementation-Specific References
- **PQCLEAN Documentation**: Details on library compilation and usage.
- **Podman Documentation**: https://podman.io (for containerized execution).

