# TetraCryptPGC: A Post-Quantum Mutually Authenticated Key Exchange Protocol

**Submission to NIST Post-Quantum Cryptography Standardization Process**  
**Proposed Candidate for Round 4 Evaluation**    
**Submitter:** [Abraxas618]    
**Repository:** [https://github.com/Abraxas618/TetraCryptPGC](https://github.com/Abraxas618/TetraCryptPGC)  
**License:** MIT License (see `LICENSE` file)

---

## Introduction

TetraCryptPGC is a cryptographic protocol designed to facilitate secure, quantum-resistant key exchange with mutual authentication. It integrates the NIST-standardized Kyber-1024 Key Encapsulation Mechanism (KEM) from the CRYSTALS-Kyber suite with the Falcon-1024 digital signature scheme, a finalist in NIST PQC Round 3. This hybrid construction ensures confidentiality, integrity, and authenticity in the presence of quantum adversaries, offering forward secrecy and resilience against both classical and quantum cryptanalytic threats. The protocol is implemented in Python, leveraging the PQCLEAN library for optimized, verified cryptographic primitives, and is packaged in a Podman container to ensure reproducibility, portability, and ease of evaluation.

### Objectives and Rationale
This submission presents TetraCryptPGC as a candidate for NIST’s ongoing evaluation of post-quantum cryptographic protocols, specifically targeting secure key exchange with mutual authentication. Unlike standalone KEMs or signature schemes, TetraCryptPGC combines these primitives into a cohesive protocol tailored for real-world applications requiring authenticated key establishment. By building on Kyber-1024 (a standardized algorithm) and Falcon-1024 (a rigorously evaluated candidate), TetraCryptPGC offers a practical, open-source solution that balances security, performance, and deployability in a post-quantum landscape.

---

## Cryptographic Design and Specification

TetraCryptPGC defines a mutually authenticated key exchange protocol, herein referred to as the TetraCrypt Post-Quantum Extended Diffie-Hellman (TetraPQ-XDH) handshake. This section details its constituent algorithms, operational steps, and security properties, adhering to NIST’s requirement for clear algorithmic specifications.

### Constituent Algorithms

#### 1. Kyber-1024 Key Encapsulation Mechanism (KEM)
- **Category:** Lattice-based cryptography.
- **Description:** Kyber-1024 is a KEM based on the Module Learning With Errors (MLWE) problem, standardized by NIST in Round 3 as part of CRYSTALS-Kyber.
- **Parameter Set:**
  - **Public Key Size:** 1568 bytes
  - **Secret Key Size:** 3168 bytes
  - **Ciphertext Size:** 1568 bytes
  - **Shared Secret Size:** 32 bytes (256 bits)
- **Security Properties:** Chosen-ciphertext secure (IND-CCA2) under the MLWE assumption.
- **Reference Implementation:** Sourced from the PQCLEAN project, compiled as `libpqclean_kyber1024_clean.so`.
- **Source Documentation:** See [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf).

#### 2. Falcon-1024 Digital Signature Scheme
- **Category:** Lattice-based cryptography.
- **Description:** Falcon-1024 is a signature scheme based on the Short Integer Solution (SIS) problem over NTRU lattices, evaluated as a finalist in NIST PQC Round 3.
- **Parameter Set:**
  - **Public Key Size:** 1281 bytes
  - **Secret Key Size:** 2305 bytes
  - **Signature Size:** Variable length, bounded by 1280 bytes (typical range: 666–1280 bytes)
- **Security Properties:** Existential unforgeability under chosen-message attacks (EUF-CMA) under the SIS assumption.
- **Reference Implementation:** Sourced from the PQCLEAN project, compiled as `libpqclean_falcon1024_clean.so`.
- **Source Documentation:** See [Falcon Specification](https://falcon-sign.info/falcon-specification-20201020.pdf).

#### 3. TetraPQ-XDH Handshake Protocol
- **Type:** Mutually authenticated key exchange protocol.
- **Overview:** The TetraPQ-XDH protocol orchestrates a single-round key exchange using Kyber-1024 for shared secret establishment, followed by Falcon-1024 signatures for mutual authentication.
- **Formal Definition:**
  - **Parties:** Two entities, denoted Alice (A) and Bob (B).
  - **Inputs:** None (keypairs are generated internally).
  - **Outputs:** 
    - Shared secret (`ss_A` for Alice, `ss_B` for Bob), 32 bytes.
    - Authentication status (`valid`), boolean.
- **Operational Steps:**
  1. **Key Pair Generation:**
     - Alice generates:
       - Kyber-1024 keypair: `(pk_A_kyber, sk_A_kyber) ← Kyber.KeyGen()`
       - Falcon-1024 keypair: `(pk_A_falcon, sk_A_falcon) ← Falcon.KeyGen()`
     - Bob generates:
       - Kyber-1024 keypair: `(pk_B_kyber, sk_B_kyber) ← Kyber.KeyGen()`
       - Falcon-1024 keypair: `(pk_B_falcon, sk_B_falcon) ← Falcon.KeyGen()`
  2. **Key Exchange Initiation:**
     - Bob encapsulates a shared secret using Alice’s Kyber public key:
       - `(ct_B, ss_B) ← Kyber.Encapsulate(pk_A_kyber)`
     - Bob sends `ct_B`, `pk_B_kyber`, and `pk_B_falcon` to Alice.
  3. **Key Exchange Completion:**
     - Alice decapsulates the shared secret:
       - `ss_A ← Kyber.Decapsulate(ct_B, sk_A_kyber)`
     - Alice sends `pk_A_kyber` and `pk_A_falcon` to Bob (if not already exchanged).
  4. **Mutual Authentication:**
     - Alice signs the shared secret:
       - `sig_A ← Falcon.Sign(ss_A, sk_A_falcon)`
     - Bob signs the shared secret:
       - `sig_B ← Falcon.Sign(ss_B, sk_B_falcon)`
     - Alice and Bob exchange signatures (`sig_A`, `sig_B`).
  5. **Verification:**
     - Alice verifies Bob’s signature:
       - `valid_B ← Falcon.Verify(ss_A, sig_B, pk_B_falcon)`
     - Bob verifies Alice’s signature:
       - `valid_A ← Falcon.Verify(ss_B, sig_A, pk_A_falcon)`
  6. **Output Determination:**
     - If `ss_A = ss_B` and `valid_A = True` and `valid_B = True`, then:
       - Return `(True, ss_A, ss_B)`
     - Otherwise, raise an exception indicating failure.
- **Security Objectives:**
  - **Confidentiality:** Ensures the shared secret is only accessible to Alice and Bob.
  - **Integrity:** Guarantees the shared secret and signatures are unaltered.
  - **Mutual Authentication:** Confirms the identities of both parties via Falcon signatures.
  - **Forward Secrecy:** Achieved through Kyber’s ephemeral key exchange; past sessions remain secure even if long-term keys are compromised.

### Security Evaluation
- **Post-Quantum Resilience:**
  - **Kyber-1024:** Provides IND-CCA2 security against quantum adversaries, with a security level exceeding AES-256 under MLWE hardness (Category 5 per NIST classification).
  - **Falcon-1024:** Offers EUF-CMA security, with a security level comparable to 256-bit classical security under SIS hardness.
- **Authentication Assurance:** The use of Falcon-1024 signatures ensures that only the holder of the corresponding secret key can authenticate the shared secret, preventing impersonation.
- **Shared Secret Strength:** The 256-bit shared secret derived from Kyber-1024 is suitable for post-quantum symmetric key applications (e.g., AES-256).
- **Vulnerability Assessment:** No known vulnerabilities are introduced beyond those inherent to Kyber-1024 and Falcon-1024, as documented in their respective NIST submissions and PQCLEAN analyses. The protocol’s simplicity minimizes additional attack surfaces.
- **Attack Resistance:** Resistant to quantum attacks (e.g., Shor’s algorithm for factorization, Grover’s algorithm for search) due to reliance on lattice problems.

### Implementation Structure
The TetraCryptPGC implementation is organized as follows:
TetraCryptPGC/
├── Dockerfile          # Container build specification for Podman
├── LICENSE             # MIT License for open-source distribution
├── README.md           # Primary documentation (this file)
├── requirements.txt    # Python dependency list (cffi>=1.15.0)
├── src/                # Source code directory
│   ├── handshake.py    # Core TetraPQ-XDH protocol implementation
│   ├── kyber_kem.py    # Kyber-1024 KEM functions
│   ├── falcon_sign.py  # Falcon-1024 signature functions
│   └── init.py     # Python module initialization
├── tests/              # Test suite directory
│   └── testhandshake.py  # Unit tests for validation
# Testing
This section explains how to test the TetraCryptPGC protocol, including generating Known Answer Tests (KATs) to verify the TetraPQ-XDH handshake works as expected.
### Generating KATs for TetraPQ-XDH: For Enterprise Users
New to TetraCryptPGC? This guide helps you generate a KAT file to confirm our post-quantum key exchange protocol works—no prior experience needed! KATs are test files that show the exact outputs of the protocol,

#### What You’ll Need
- A Linux computer (e.g., Ubuntu) or a VM/cloud instance (Windows/Mac users can use WSL2 or a VM).
- Internet access.
- 15-20 minutes for setup.

#### Steps

1. **Get the Code**  
   Open a terminal and run:  
   ```bash
   git clone https://github.com/Abraxas618/TetraCryptPGC.git
   cd TetraCryptPGC

   Note: If “git” isn’t found, install it:  
sudo apt update && sudo apt install -y git

Install Podman
Podman runs our code in a pre-set environment:  

sudo apt update
sudo apt install -y podman

Build the Environment
Create the TetraCryptPGC container:

podman build -t tetrapgc-nist .

Wait 5-15 minutes—it’s ready when you see “Successfully tagged.”

Generate the KAT File  

mkdir -p KAT
podman run --rm -v $(pwd)/KAT:/app/KAT tetrapgc-nist python3 generate_kat.py

Check the result:  

cat KAT/tetrapq_xdh_kat.txt

You’ll see keys, secrets, and verification results.

Next Steps
Save KAT/tetrapq_xdh_kat.txt for your records or audits.
Troubleshooting
“No such image”: Run the build command again.  
No output file: Ensure KAT/ exists (mkdir -p KAT) and retry.  
