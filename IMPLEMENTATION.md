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
This document outlines the implementation of the TetraCryptPGC protocol, a post-quantum key exchange with mutual authentication using Kyber-1024 and Falcon-1024. The software is written in Python 3, uses liboqs’s C libraries via `cffi`, and is containerized with Podman for reproducibility.

---

## 2. Software Architecture
The implementation is organized into modular Python scripts:

### **Directory Structure**
```
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
```

### **Components**
- `kyber_kem.py`: Handles Kyber-1024 key generation, encapsulation, and decapsulation.
- `falcon_sign.py`: Manages Falcon-1024 key generation, signing, and verification.
- `handshake.py`: Executes the full TetraPQ-XDH handshake.
- `testhandshake.py`: Tests all components and the handshake.

---

## 3. Dependencies
- **liboqs**: Provides post-quantum cryptographic algorithms (https://github.com/open-quantum-safe/liboqs).
- **Python**: Version 3.8+ with `cffi>=1.15.0` (install via `pip3 install -r requirements.txt`).
- **Podman**: Version 4.0+ for containerized builds (install via `sudo apt install podman` on Ubuntu).

---

## 4. Building the Implementation

### **4.1 Containerized Build with Podman**
**Command:**
```bash
podman build -t tetrapgc-nist .
```
This process installs dependencies, compiles libraries, and sets up Python with `cffi`.

### **4.2 Local Build Without Container**
**Steps:**
1. Install prerequisites:
```bash
sudo apt install -y python3 python3-pip build-essential cmake clang git
pip3 install -r requirements.txt
```
2. Build liboqs:
```bash
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/app/local ..
make -j$(nproc)
make install
```

---

## 5. Library Path Configuration
### **Environment Variables:**
- `KYBER_LIB_PATH`: Path to `liboqs.so` (default: `/app/local/lib/liboqs.so` in container).
- `FALCON_LIB_PATH`: Path to Falcon library (default: `/app/local/lib/liboqs.so` in container).

**Set Locally:**
```bash
export KYBER_LIB_PATH=/path/to/liboqs/liboqs.so
export FALCON_LIB_PATH=/path/to/liboqs/liboqs.so
export LD_LIBRARY_PATH=/path/to/liboqs:$LD_LIBRARY_PATH
```

---

## 6. Error Handling
- **Key Generation:** Raises `ValueError` if key sizes are incorrect.
- **Key Exchange:** Raises `KeyMismatchError` if shared secrets don’t match.
- **Authentication:** Raises `AuthenticationError` if signatures fail verification.
- **Library Loading:** Raises `OSError` if library paths are invalid.

---

## 7. Performance Considerations
- **Kyber-1024:** Keygen ~1-2 ms, Encapsulation/Decapsulation ~2-3 ms.
- **Falcon-1024:** Keygen ~50-100 ms, Signing ~20-50 ms, Verification ~5-10 ms.
- **Full Handshake:** ~100-150 ms, dominated by Falcon operations.
- **Memory Usage:** ~50-100 MB peak during execution.

---

## 8. Testing and Validation
### **Unit Tests**
The `testhandshake.py` script verifies key generation, encapsulation, signing, and handshake.

**Run Tests:**
```bash
podman run --rm tetrapgc-nist  # Run tests in container
python3 tests/testhandshake.py  # Run locally
```
**Expected Output:**
```
Ran 4 tests in X.XXXs
OK
```

---

## 9. Usage Examples
### **Containerized Execution**
```bash
podman run --rm tetrapgc-nist  # Run tests
podman run --rm -it tetrapgc-nist python3 src/handshake.py  # Run handshake
```
### **Local Execution**
```bash
python3 tests/testhandshake.py  # After setting paths
python3 src/handshake.py
```

---

## 10. Notes for Evaluators
- The implementation is reproducible via Podman or local build.
- Known Answer Tests (KATs) can be generated with `generate_kat.py` (optional, see `KAT/`).

