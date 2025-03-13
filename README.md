# TetraCryptPGC: Post-Quantum Cryptography Toolkit

## Overview
TetraCryptPGC is a post-quantum cryptographic framework designed to provide secure key exchange and authentication using lattice-based algorithms. The implementation integrates **Kyber-1024** (Key Encapsulation Mechanism) and **Falcon-1024** (Digital Signature Scheme) to ensure confidentiality, integrity, and mutual authentication in a quantum-resistant manner.

## Features
- **Post-Quantum Secure Handshake** using Kyber-1024 and Falcon-1024.
- **Hybrid PQC + ECC Mode** for smooth transition from classical cryptography.
- **Support for Hardware Security Modules (HSM), TPM, and SGX**.
- **Multi-Factor Authentication (MFA) and Zero Trust Security**.
- **Quantum Key Distribution (QKD) Integration** as primary key exchange.
- **Podman-based containerized deployment** for reproducibility.

## Components
The project is structured as follows:
```
TetraCryptPGC/
├── Dockerfile           # Podman build script
├── README.md            # Documentation
├── requirements.txt     # Python dependencies
├── src/
│   ├── kyber_kem.py     # Kyber-1024 KEM functions
│   ├── falcon_sign.py   # Falcon-1024 signature functions
│   ├── handshake.py     # Post-Quantum Extended Diffie-Hellman (PQ-XDH)
│   ├── qkd_monitor.py   # QKD monitoring and fallback mechanism
│   ├── secure_enclave.py # SGX, TPM, and TrustZone integrations
├── tests/
│   ├── test_handshake.py # Unit tests for key exchange
│   ├── test_security.py  # Security compliance tests
│   ├── test_hybrid.py    # Hybrid PQC + ECC handshake verification
```

## Installation
### Prerequisites
Ensure the following dependencies are installed:
```bash
sudo apt install -y python3 python3-pip build-essential cmake clang git
pip3 install -r requirements.txt
```

### Building with Podman
To build and deploy using Podman:
```bash
podman build -t tetrapgc .
podman run --rm tetrapgc
```

### Manual Build
```bash
git clone https://github.com/Abraxas618/TetraCryptPGC.git
cd TetraCryptPGC
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage
### Running the Handshake Protocol
To execute the PQ-XDH handshake with Kyber-1024 and Falcon-1024:
```bash
python3 src/handshake.py
```

### Running Unit Tests
```bash
python3 -m unittest discover -s tests
```

## Security Features
### Post-Quantum Cryptography
- **Kyber-1024** for secure key encapsulation.
- **Falcon-1024** for mutual authentication.
- **Dilithium-3 (optional)** as an alternative signature scheme.

### Zero Trust Security
- Multi-Factor Authentication (MFA) using smart cards.
- Remote attestation with TPM and SGX.
- Quantum entropy analysis for QKD validation.

## Deployment
### Kubernetes Deployment
Use `tetrapqc_deployment.yaml` for container orchestration:
```bash
kubectl apply -f tetrapqc_deployment.yaml
```

### Secure Storage with HSM
Enable HSM storage for keys:
```bash
export USE_HSM=true
```

## Roadmap
- **FIPS 140-3 Certification Compliance**
- **Full QKD Integration with ID Quantique Systems**
- **Expansion to Dilithium Signatures for Flexible Authentication**
- **Further Performance Optimization for Large-Scale Deployments**

## References
- **NIST PQC Standardization**: [https://csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- **Kyber-1024 Specification**: [https://pq-crystals.org/kyber](https://pq-crystals.org/kyber)
- **Falcon-1024 Specification**: [https://falcon-sign.info](https://falcon-sign.info)
- **PQCLEAN Library**: [https://github.com/PQClean/PQClean](https://github.com/PQClean/PQClean)

## License
TetraCryptPGC is licensed under the MIT License. See the `LICENSE` file for details.

