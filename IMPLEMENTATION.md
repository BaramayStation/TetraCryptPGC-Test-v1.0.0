# Implementation Notes for TetraCryptPGC

**Submission to NIST Post-Quantum Cryptography Standardization Process**  
**Proposed Candidate for Round 4 Evaluation**  
**Submission Date:** March 11, 2025  
**Submitter:** [Abraxas618]  
**Contact Email:** [Redbull1956@protonmail.com]  
**Repository:** [https://github.com/Abraxas618/TetraCryptPGC](https://github.com/Abraxas618/TetraCryptPGC)  
**License:** MIT License (see `LICENSE` file)

---

## 1. Introduction
This document outlines the implementation of the TetraCryptPGC protocol, a post-quantum key exchange with mutual authentication using Kyber-1024 and Falcon-1024. The software is written in Python 3, uses PQCLEAN’s C libraries via `cffi`, and is containerized with Podman for reproducibility.

---

## 2. Software Architecture
The implementation is organized into modular Python scripts:
- **Directory Structure**:
TetraCryptPGC/
  ├── Dockerfile          # Podman build script
  ├── LICENSE             # MIT License
  ├── README.md           # General documentation
  ├── requirements.txt    # Python dependencies
  ├── src/
  │   ├── kyber_kem.py    # Kyber-1024 KEM functions
  │   ├── falcon_sign.py  # Falcon-1024 signature functions
  │   ├── handshake.py    # TetraPQ-XDH protocol
  ├── tests/
  │   └── testhandshake.py  # Unit tests
- **Components**:
- `kyber_kem.py`: Handles Kyber-1024 key generation, encapsulation, and decapsulation.
- `falcon_sign.py`: Manages Falcon-1024 key generation, signing, and verification.
- `handshake.py`: Executes the full TetraPQ-XDH handshake.
- `testhandshake.py`: Tests all components and the handshake.

---

## 3. Dependencies
- **PQCLEAN**: Provides `libpqclean_kyber1024_clean.so` and `libpqclean_falcon1024_clean.so` (https://github.com/PQClean/PQClean).
- **Python**: Version 3.8+ with `cffi>=1.15.0` (install via `pip3 install -r requirements.txt`).
- **Podman**: Version 4.0+ for containerized builds (install via `sudo apt install podman` on Ubuntu).

---

## 4. Building the Implementation
### 4.1 Containerized Build with Podman
- **Command**:
```bash
podman build -t tetrapgc-nist .
Process: The Dockerfile installs Ubuntu 24.04, build tools, clones PQCLEAN, compiles libraries, and sets up Python with cffi.

4.2 Local Build Without Container
Steps:
Install prerequisites:
bash

sudo apt install -y python3 python3-pip build-essential cmake clang git
pip3 install cffi>=1.15.0

Build PQCLEAN libraries:
bash

git clone https://github.com/PQClean/PQClean.git
cd PQClean
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON ..
make
cp crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so ../lib/
cp crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so ../lib/

5. Library Path Configuration
Environment Variables:
KYBER_LIB_PATH: Path to libpqclean_kyber1024_clean.so (default: /app/lib/libpqclean_kyber1024_clean.so in container).

FALCON_LIB_PATH: Path to libpqclean_falcon1024_clean.so (default: /app/lib/libpqclean_falcon1024_clean.so in container).

Set Locally:
bash

export KYBER_LIB_PATH=/path/to/PQClean/lib/libpqclean_kyber1024_clean.so
export FALCON_LIB_PATH=/path/to/PQClean/lib/libpqclean_falcon1024_clean.so
export LD_LIBRARY_PATH=/path/to/PQClean/lib:$LD_LIBRARY_PATH

6. Error Handling
Key Generation: Raises ValueError if key sizes are incorrect (e.g., Kyber pk ≠ 1568 bytes).

Key Exchange: Raises KeyMismatchError if shared secrets don’t match.

Authentication: Raises AuthenticationError if signatures fail verification.

Library Loading: Raises OSError if library paths are invalid.

7. Performance Considerations
Kyber-1024: Keygen ~1-2 ms, Encapsulation/Decapsulation ~2-3 ms.

Falcon-1024: Keygen ~50-100 ms, Signing ~20-50 ms, Verification ~5-10 ms.

Full Handshake: ~100-150 ms, dominated by Falcon operations.

Memory: ~50-100 MB peak during execution.

8. Testing and Validation
Unit Tests: testhandshake.py verifies keygen, encapsulation, signing, and handshake.
Run: podman run --rm tetrapgc-nist or python3 tests/testhandshake.py.

Output: "Ran 4 tests in X.XXXs OK" on success.

9. Usage Examples
Containerized:
bash

podman run --rm tetrapgc-nist  # Run tests
podman run --rm -it tetrapgc-nist python3 src/handshake.py  # Run handshake

Local:
bash

python3 tests/testhandshake.py  # After setting paths
python3 src/handshake.py

10. Notes for Evaluators
The implementation is reproducible via Podman or local build.

Known Answer Tests (KATs) can be generated with generate_kat.py (optional, see KAT/).

