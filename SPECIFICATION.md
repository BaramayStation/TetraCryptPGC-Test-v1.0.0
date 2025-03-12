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

The protocol proceeds as follows:

#### Step 1: Key Pair Generation
- **Alice’s Actions**:
  - Generate a Kyber-1024 key pair: `(pk_A_kyber, sk_A_kyber) ← Kyber.KeyGen()`
    - `pk_A_kyber`: 1568-byte public key.
    - `sk_A_kyber`: 3168-byte secret key.
  - Generate a Falcon-1024 key pair: `(pk_A_falcon, sk_A_falcon) ← Falcon.KeyGen()`
    - `pk_A_falcon`: 1281-byte public key.
    - `sk_A_falcon`: 2305-byte secret key.
- **Bob’s Actions**:
  - Generate a Kyber-1024 key pair: `(pk_B_kyber, sk_B_kyber) ← Kyber.KeyGen()`
    - `pk_B_kyber`: 1568-byte public key.
    - `sk_B_kyber`: 3168-byte secret key.
  - Generate a Falcon-1024 key pair: `(pk_B_falcon, sk_B_falcon) ← Falcon.KeyGen()`
    - `pk_B_falcon`: 1281-byte public key.
    - `sk_B_falcon`: 2305-byte secret key.
- **Purpose**: Each party generates ephemeral key pairs for the key exchange (Kyber) and long-term or session-specific key pairs for authentication (Falcon). Ephemeral keys ensure forward secrecy, while Falcon keys enable identity verification.

#### Step 2: Key Exchange Initiation
- **Bob’s Actions**:
  - Using Alice’s public Kyber key, encapsulate a shared secret:
    - `(ct_B, ss_B) ← Kyber.Encapsulate(pk_A_kyber)`
    - `ct_B`: 1568-byte ciphertext.
    - `ss_B`: 32-byte shared secret.
  - Transmit to Alice:
    - `ct_B` (ciphertext).
    - `pk_B_kyber` (Bob’s Kyber public key).
    - `pk_B_falcon` (Bob’s Falcon public key).
- **Message Size**: 
  - Total = 1568 (ct_B) + 1568 (pk_B_kyber) + 1281 (pk_B_falcon) = 4417 bytes.
- **Purpose**: Bob initiates the key exchange by encapsulating a shared secret that only Alice can decapsulate, leveraging Kyber’s IND-CCA2 security. Public keys are shared to enable subsequent authentication.

#### Step 3: Key Exchange Completion
- **Alice’s Actions**:
  - Decapsulate the shared secret using her Kyber secret key:
    - `ss_A ← Kyber.Decapsulate(ct_B, sk_A_kyber)`
    - `ss_A`: 32-byte shared secret (should match `ss_B` if successful).
  - Transmit to Bob (if not previously sent):
    - `pk_A_kyber` (Alice’s Kyber public key).
    - `pk_A_falcon` (Alice’s Falcon public key).
- **Message Size** (if sent here): 
  - Total = 1568 (pk_A_kyber) + 1281 (pk_A_falcon) = 2849 bytes.
- **Purpose**: Alice completes the key exchange by recovering the shared secret. If `pk_A_kyber` and `pk_A_falcon` were sent earlier (e.g., in a pre-exchange phase), this step only involves decapsulation.

#### Step 4: Mutual Authentication
- **Alice’s Actions**:
  - Sign the shared secret with her Falcon private key:
    - `sig_A ← Falcon.Sign(ss_A, sk_A_falcon)`
    - `sig_A`: Variable-length signature (up to 1280 bytes, typically 666–1280 bytes).
  - Send `sig_A` to Bob.
- **Bob’s Actions**:
  - Sign the shared secret with his Falcon private key:
    - `sig_B ← Falcon.Sign(ss_B, sk_B_falcon)`
    - `sig_B`: Variable-length signature (up to 1280 bytes).
  - Send `sig_B` to Alice.
- **Message Size**: 
  - Each signature: Up to 1280 bytes (assume 1280 for worst-case analysis).
- **Purpose**: Both parties authenticate by signing the shared secret, ensuring that only the legitimate key holder could produce a valid signature. This step prevents man-in-the-middle attacks.

#### Step 5: Verification
- **Alice’s Actions**:
  - Verify Bob’s signature using his Falcon public key:
    - `valid_B ← Falcon.Verify(ss_A, sig_B, pk_B_falcon)`
    - Returns `True` if the signature is valid, `False` otherwise.
- **Bob’s Actions**:
  - Verify Alice’s signature using her Falcon public key:
    - `valid_A ← Falcon.Verify(ss_B, sig_A, pk_A_falcon)`
    - Returns `True` if the signature is valid, `False` otherwise.
- **Purpose**: Verification ensures that the shared secret was generated and signed by the intended parties, achieving mutual authentication.

#### Step 6: Output Determination
- **Conditions for Success**:
  - Check: `ss_A == ss_B` (implicitly verified by both parties using the same value in signatures).
  - Check: `valid_A == True` (Bob’s verification).
  - Check: `valid_B == True` (Alice’s verification).
- **Output**:
  - If all conditions hold:
    - Return `(True, ss_A, ss_B)` where `ss_A = ss_B`.
  - If any condition fails:
    - Raise an exception:
      - `KeyMismatchError` if `ss_A ≠ ss_B` (detected via signature mismatch).
      - `AuthenticationError` if `valid_A` or `valid_B` is `False`.
- **Purpose**: Ensures the protocol only succeeds if both the key exchange and authentication are valid, providing a secure shared secret.

### 4.3 Security Properties
- **Confidentiality**: 
  - Guaranteed by Kyber-1024’s IND-CCA2 security, ensuring the shared secret remains secret even against chosen-ciphertext attacks by quantum or classical adversaries.
- **Integrity**: 
  - Protected by Falcon-1024’s EUF-CMA security, ensuring that signatures cannot be forged, thus preserving the integrity of the authenticated shared secret.
- **Mutual Authentication**: 
  - Achieved through bidirectional signature verification, confirming each party’s identity via their Falcon-1024 key pairs.
- **Forward Secrecy**: 
  - Provided by the ephemeral nature of Kyber-1024 key pairs; compromise of long-term Falcon keys does not affect past session keys.
- **Additional Considerations**: 
  - The protocol is resistant to replay attacks if nonces or timestamps are incorporated (optional extension, not specified here but recommended for production use).

### 4.4 Security Assumptions
- **Kyber-1024**: Relies on the hardness of the Module Learning With Errors (MLWE) problem in the quantum random oracle model.
- **Falcon-1024**: Relies on the hardness of the Short Integer Solution (SIS) problem over NTRU lattices.
- **Hash Functions**: If a hash (e.g., SHA-256) is used in signature generation (per Falcon’s design), its collision resistance is assumed.
- **Randomness**: Assumes cryptographically secure random number generation for key pair generation and encapsulation.

### 4.5 Communication Overhead
- **Total Messages**: 2 (one from Bob to Alice, one from Alice to Bob, assuming pre-shared public keys are optional).
- **Bandwidth**:
  - Bob → Alice: 4417 bytes (ct_B + pk_B_kyber + pk_B_falcon).
  - Alice → Bob: Up to 4129 bytes (pk_A_kyber + pk_A_falcon + sig_A, if all sent together).
  - Alice → Bob (sig only): Up to 1280 bytes.
  - Bob → Alice (sig only): Up to 1280 bytes.
- **Total (worst case)**: ~10 KB for a full exchange, depending on signature sizes and pre-sharing.

## 5. Parameter Selection

### 5.1 Rationale for Kyber-1024
- **Selection**: Kyber-1024 is chosen as the KEM component due to its standardization by NIST in Round 3 as part of CRYSTALS-Kyber, ensuring a well-vetted, widely accepted post-quantum primitive.
- **Security Level**: 
  - Offers Category 5 security (exceeding AES-256) against both classical and quantum adversaries, based on MLWE hardness.
  - Provides a 256-bit shared secret, sufficient for modern symmetric cryptography (e.g., AES-256, SHA-256).
- **Performance**: 
  - Balances efficiency and security with reasonable key and ciphertext sizes (1568 bytes each).
  - Faster encapsulation/decapsulation compared to higher-parameter variants (e.g., Kyber-1024 vs. Kyber-768).
- **Compatibility**: Aligns with NIST’s standardized parameter set, facilitating integration into existing systems.

### 5.2 Rationale for Falcon-1024
- **Selection**: Falcon-1024 is selected for authentication due to its status as a Round 3 finalist, offering a robust lattice-based signature scheme with strong security guarantees.
- **Security Level**: 
  - Provides EUF-CMA security equivalent to 256-bit classical security under SIS hardness.
  - Resistant to quantum attacks, complementing Kyber’s post-quantum properties.
- **Performance**: 
  - Generates compact signatures (typically 666–1280 bytes) and public keys (1281 bytes), minimizing overhead in the handshake.
  - Signing and verification are computationally efficient for lattice-based signatures, though slower than classical schemes like ECDSA.
- **Trade-offs**: 
  - Chosen over Falcon-512 for higher security, despite larger key sizes, to match Kyber-1024’s strength.
  - Variable signature size is managed by bounding at 1280 bytes for predictability.

### 5.3 Shared Secret Size
- **Size**: 32 bytes (256 bits).
- **Rationale**: 
  - Matches Kyber-1024’s output, ensuring compatibility.
  - Provides sufficient entropy for deriving symmetric keys (e.g., AES-256 requires 256 bits).
  - Aligns with NIST’s guidelines for post-quantum key lengths (256 bits exceeds Grover’s algorithm bounds).
- **Usage**: The shared secret can be used directly or hashed (e.g., SHA-256) for key derivation in applications.

### 5.4 Design Considerations
- **Single-Round Exchange**: 
  - Kyber’s single encapsulation reduces round trips, improving latency over multi-round protocols.
- **Ephemeral vs. Static Keys**: 
  - Kyber keys are ephemeral for forward secrecy; Falcon keys may be static (long-term) or ephemeral (session-specific), offering flexibility.
- **Interoperability**: 
  - Parameters align with NIST-standardized (Kyber) and finalist (Falcon) schemes, easing adoption.

### 5.5 Alternative Parameters
- **Kyber-512/768**: Rejected due to lower security levels (Category 1/3) insufficient for maximal post-quantum protection.
- **Falcon-512**: Considered but discarded for lower security (~128-bit equivalent), prioritizing consistency with Kyber-1024’s strength.

## 6. References

### 6.1 Primary Sources
- **[1] CRYSTALS-Kyber Specification**: 
  - Title: "CRYSTALS-Kyber: Algorithm Specification and Supporting Documentation."
  - Authors: Roberto Avanzi et al.
  - Date: August 4, 2021 (Round 3 submission).
  - URL: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
  - Description: Defines Kyber-1024’s parameters, security proofs, and implementation details.
- **[2] Falcon Specification**: 
  - Title: "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU."
  - Authors: Pierre-Alain Fouque et al.
  - Date: October 20, 2020 (Round 3 submission).
  - URL: https://falcon-sign.info/falcon-specification-20201020.pdf
  - Description: Specifies Falcon-1024’s design, security analysis, and performance metrics.

### 6.2 Supporting References
- **[3] PQCLEAN Project**: 
  - URL: https://github.com/PQClean/PQClean
  - Description: Provides clean, portable C implementations of Kyber-1024 and Falcon-1024, used as the cryptographic backend for TetraCryptPGC.
  - Commit: Latest as of March 11, 2025 (or specify commit hash if fixed).
- **[4] NIST PQC Standardization Process**: 
  - Title: "Post-Quantum Cryptography Standardization: Round 3 Call for Proposals."
  - URL: https://csrc.nist.gov/projects/post-quantum-cryptography
  - Description: Outlines submission requirements and evaluation criteria.

### 6.3 Additional Reading
- **Lattice Cryptography**: 
  - "Lattice-Based Cryptography" by Chris Peikert (survey paper on MLWE and SIS problems).
- **Key Exchange Protocols**: 
  - RFC 7748: "Elliptic Curves for Security" (classical XDH inspiration, adapted for post-quantum use).
- **Security Models**: 
  - "IND-CCA Security" by Mihir Bellare et al.; "EUF-CMA Security" by Jonathan Katz (standard definitions).

### 6.4 Implementation-Specific References
- **PQCLEAN Documentation**: Details on library compilation and usage.
- **Podman Documentation**: https://podman.io (for containerized execution).