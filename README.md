## Overview

TetraCryptPGC is a post-quantum authenticated key exchange protocol combining the NIST-standardized Kyber-1024 key encapsulation mechanism (KEM) with the Falcon-1024 digital signature scheme (Round 3 finalist). This hybrid protocol provides mutual authentication and forward-secure key exchange, resistant to quantum computer attacks. It is implemented in Python with bindings to the PQCLEAN library, containerized using Podman for reproducibility and portability.

### Purpose
This submission proposes TetraCryptPGC as a candidate for NIST’s evaluation of post-quantum cryptographic protocols, focusing on secure key exchange with mutual authentication. It leverages standardized and well-vetted primitives to offer a practical, open-source solution for post-quantum security.

---

## Algorithm Specification

### Components
1. **Kyber-1024 KEM**:
   - **Type:** Lattice-based Key Encapsulation Mechanism.
   - **Parameters:** 
     - Public key size: 1568 bytes
     - Secret key size: 3168 bytes
     - Ciphertext size: 1568 bytes
     - Shared secret size: 32 bytes
   - **Source:** NIST PQC Round 3 standardized algorithm (CRYSTALS-Kyber).
   - **Implementation:** PQCLEAN (`libpqclean_kyber1024_clean.so`).

2. **Falcon-1024 Signature Scheme**:
   - **Type:** Lattice-based Digital Signature.
   - **Parameters:**
     - Public key size: 1281 bytes
     - Secret key size: 2305 bytes
     - Signature size: Variable, up to 1280 bytes (typically 666–1280 bytes)
   - **Source:** NIST PQC Round 3 finalist.
   - **Implementation:** PQCLEAN (`libpqclean_falcon1024_clean.so`).

3. **TetraCryptPGC Handshake**:
   - **Protocol:** Mutual-authentication post-quantum extended Diffie-Hellman (XDH).
   - **Steps:**
     1. **Key Generation**: Both parties (Alice and Bob) generate Kyber-1024 and Falcon-1024 keypairs.
     2. **Key Exchange**: Bob encapsulates a 32-byte shared secret using Alice’s Kyber public key; Alice decapsulates it.
     3. **Authentication**: Both parties sign the shared secret with their Falcon secret keys and verify each other’s signatures.
     4. **Validation**: Success requires matching shared secrets and valid signatures.
   - **Security Goals:** Confidentiality, integrity, mutual authentication, forward secrecy.

### Security Analysis
- **Quantum Resistance**: Inherits Kyber’s IND-CCA2 security and Falcon’s EUF-CMA security, both proven resistant to quantum attacks under lattice assumptions.
- **Authentication**: Falcon signatures ensure both parties’ identities are verified.
- **Key Strength**: 256-bit shared secret (post-quantum secure).
- **Known Attacks**: No additional vulnerabilities introduced beyond those of Kyber and Falcon (see PQCLEAN documentation for base algorithm analyses).

### Directory Structure
TetraCryptPGC/
├── Dockerfile          # Podman-compatible build file
├── LICENSE             # MIT License
├── README.md           # This file
├── requirements.txt    # Python dependencies (cffi>=1.15.0)
├── src/
│   ├── handshake.py    # Main handshake protocol
│   ├── kyber_kem.py    # Kyber-1024 KEM implementation
│   ├── falcon_sign.py  # Falcon-1024 signature implementation
│   └── init.py     # Module definition
├── tests/
│   └── testhandshake.py  # Unit tests

### Dependencies
- **PQCLEAN**: Clean implementations of Kyber-1024 and Falcon-1024 (compiled as shared libraries).
- **Python**: Version 3.x with `cffi` for FFI bindings.
- **Podman**: Container runtime for building and testing.

### Configurable Library Paths
- **Environment Variables**:
  - `KYBER_LIB_PATH`: Path to `libpqclean_kyber1024_clean.so` (default: `/app/lib/libpqclean_kyber1024_clean.so`).
  - `FALCON_LIB_PATH`: Path to `libpqclean_falcon1024_clean.so` (default: `/app/lib/libpqclean_falcon1024_clean.so`).
- Allows flexibility for local or custom deployments.

---

## Building and Running with Podman

### Prerequisites
- **Podman**: Install via package manager (e.g., `sudo apt install podman` on Ubuntu).
- **Git**: For cloning the repository.

### Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Abraxas618/TetraCryptPGC.git
   cd TetraCryptPGC
