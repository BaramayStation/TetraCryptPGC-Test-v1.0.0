TetraCryptPGC: Post-Quantum Cryptography & Secure Key Exchange Suite

Overview

TetraCryptPGC is an advanced post-quantum cryptographic (PQC) suite designed for secure communication and key exchange in zero-trust environments. It integrates cutting-edge cryptographic algorithms with Quantum Key Distribution (QKD), Hardware Security Modules (HSM), Secure Enclaves (SGX & TrustZone), and Multi-Party Computation (MPC) to provide a future-proof cryptographic infrastructure.

This version has undergone a full security audit and now complies with:

NIST PQC Standards (Kyber, Falcon, Dilithium)

FIPS 140-3 Compliance

Zero-Trust Security Model

Kubernetes Security Best Practices

SonarCloud Code Quality & Security Fixes

Features

🔹 Post-Quantum Cryptography (PQC) Algorithms

Kyber-1024 – Post-Quantum Key Encapsulation Mechanism (KEM)

Falcon-1024 – Digital Signature Algorithm

Dilithium-3 – Additional PQC Signature Scheme

Hybrid ECC+PQC – Combines X25519/P-384 with Kyber for transition security

🔹 Quantum Key Distribution (QKD) Integration

BB84 QKD Protocol (Simulated)

ID Quantique Real QKD Support

QKD Key Integrity Validation (HMAC-based entropy verification)

QKD Anomaly Detection & Monitoring

🔹 Secure Key Management & Rotation

HSM (Hardware Security Module) Support for non-exportable key storage

SGX & TrustZone Secure Enclaves for key protection

Automated Key Rotation & Revocation (NIST-recommended destruction)

Multi-Party Computation (MPC) Key Sharing for distributed trust

🔹 Zero Trust Architecture & Authentication

Mandatory Multi-Factor Authentication (MFA)

Remote Attestation via Intel SGX

TLS 1.3 Enforcement for Encrypted Communication

Real-Time Intrusion Detection & Logging

🔹 Secure Kubernetes Deployment

Pod Security Policies (PSP) & RBAC Enforcement

Container Isolation via Seccomp & AppArmor

TLS Encryption for Inter-Container Communication

Podman Compatibility (No root privileges required)

Installation & Setup

1️⃣ Clone the Repository

If Git is working:

git clone https://github.com/Abraxas618/TetraCryptPGC.git
cd TetraCryptPGC

If Git is NOT working:

Download ZIP from GitHub and extract manually.

Use GitHub Desktop to clone the repository.

2️⃣ Install Dependencies

Ensure you have Python 3.9+ and the required dependencies:

pip install -r requirements.txt

For secure execution, make sure you have SGX, TrustZone, and HSM drivers installed (if applicable).

3️⃣ Running the Secure Handshake

To execute the full PQ-XDH Handshake with QKD:

python src/pq_xdh_handshake_mutual.py

4️⃣ Running the Tests

Ensure all cryptographic functions work correctly:

python -m unittest discover tests

Deployment (Kubernetes & Docker)

1️⃣ Kubernetes Deployment

kubectl apply -f kubernetes/tetrapgc-deployment.yaml

Ensure:

Pod security policies are enabled

TLS certificates are properly configured

HSM & Secure Enclaves are accessible in cluster

2️⃣ Podman/Docker Deployment

Podman (Rootless Execution)

podman build -t tetrapgc .
podman run --security-opt=seccomp=default.json --user tetrapgc tetrapgc

Docker Execution

docker build -t tetrapgc .
docker run --rm -it --security-opt seccomp=default.json tetrapgc

Security Enhancements in This Version

✅ Removed Hardcoded IPs in QKD Client (Now environment-configurable)
✅ Fixed Root Privilege Issues (Non-root base image & enforced user switching)
✅ Addressed All SonarCloud Code Smells & Security Issues
✅ Enforced Secure Kubernetes Deployment Policies
✅ Implemented Advanced Key Revocation & Rotation Mechanisms
✅ Enhanced Intrusion Detection & Security Logging

Contributing

We welcome contributions to improve the security and efficiency of TetraCryptPGC. If you would like to contribute:

Fork the repository

Create a feature branch (feature-improvement)

Submit a pull request with detailed changes

Please ensure all security best practices are followed before submission.

License

TetraCryptPGC is licensed under the MIT License. See LICENSE for more details.

📌 GitHub Repository: https://github.com/Abraxas618/TetraCryptPGC

