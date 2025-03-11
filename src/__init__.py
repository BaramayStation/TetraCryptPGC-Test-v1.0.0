"""
TetraCryptPGC: Post-Quantum Cryptography Toolkit

This package implements a post-quantum secure XDH handshake using:
- **Kyber-1024** (Key Encapsulation Mechanism)
- **Falcon-1024** (Digital Signatures)
- **Hybrid Key Derivation (HKDF)**
- **Secure Enclave Support (SGX, TPM, HSM)**
- **Multi-Factor Authentication (MFA)**
- **Multi-Party Computation (MPC) for Key Sharing**
- **Post-Quantum Hybrid Mode (PQC + ECC Transition)**
- **TPM-Based Remote Attestation for Device Integrity Verification**

Complies with NIST post-quantum cryptography standards and FIPS 140-2/3 validation.
"""

import logging
from importlib import import_module

__version__ = "1.2.0"
__author__ = "Abraxas618"
__license__ = "MIT"

# Enable structured logging for security audits
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Kyber KEM (Post-Quantum Key Exchange)
try:
    kyber = import_module("src.kyber_kem")
    kyber_keygen = kyber.kyber_keygen
    kyber_encapsulate = kyber.kyber_encapsulate
    kyber_decapsulate = kyber.kyber_decapsulate
    logging.info("Kyber-1024 Loaded Successfully")
except ImportError as e:
    logging.error("Kyber-1024 Module Not Found: %s", e)
    kyber_keygen = kyber_encapsulate = kyber_decapsulate = None

# Falcon Signatures (Post-Quantum Authentication)
try:
    falcon = import_module("src.falcon_sign")
    falcon_keygen = falcon.falcon_keygen
    falcon_sign = falcon.falcon_sign
    falcon_verify = falcon.falcon_verify
    logging.info("Falcon-1024 Loaded Successfully")
except ImportError as e:
    logging.error("Falcon-1024 Module Not Found: %s", e)
    falcon_keygen = falcon_sign = falcon_verify = None

# Post-Quantum Mutual Authentication Handshake
try:
    handshake = import_module("src.handshake")
    pq_xdh_handshake_mutual = handshake.pq_xdh_handshake_mutual
    logging.info("PQC XDH Handshake Loaded Successfully")
except ImportError as e:
    logging.error("PQC XDH Handshake Module Not Found: %s", e)
    pq_xdh_handshake_mutual = None

# Multi-Party Computation (MPC) Key Sharing
try:
    mpc = import_module("src.mpc_key_sharing")
    generate_mpc_key_shares = mpc.generate_mpc_key_shares
    reconstruct_secret = mpc.reconstruct_secret
    logging.info("MPC Key Sharing Loaded Successfully")
except ImportError as e:
    logging.error("MPC Key Sharing Module Not Found: %s", e)
    generate_mpc_key_shares = reconstruct_secret = None

# Secure Enclave (SGX, TPM, HSM) Support
try:
    enclave = import_module("src.secure_enclave")
    secure_store_key = enclave.secure_store_key
    retrieve_secure_key = enclave.retrieve_secure_key
    logging.info("Secure Enclave (SGX, TPM) Support Loaded")
except ImportError as e:
    logging.warning("Secure Enclave Support Not Available: %s", e)
    secure_store_key = retrieve_secure_key = None

# Multi-Factor Authentication (MFA) Support
try:
    mfa = import_module("src.mfa_auth")
    authenticate_with_mfa = mfa.authenticate_with_mfa
    logging.info("MFA Authentication Loaded Successfully")
except ImportError as e:
    logging.warning("MFA Module Not Available: %s", e)
    authenticate_with_mfa = None

# Hybrid PQC + ECC Transition Support
try:
    hybrid_pqc = import_module("src.hybrid_pqc")
    hybrid_key_exchange = hybrid_pqc.hybrid_key_exchange
    logging.info("Hybrid PQC + ECC Support Loaded")
except ImportError as e:
    logging.warning("Hybrid PQC Module Not Available: %s", e)
    hybrid_key_exchange = None

# TPM-Based Remote Attestation for Integrity Verification
try:
    tpm = import_module("src.tpm_attestation")
    tpm_verify_device = tpm.tpm_verify_device
    logging.info("TPM-Based Remote Attestation Loaded Successfully")
except ImportError as e:
    logging.warning("TPM Remote Attestation Module Not Available: %s", e)
    tpm_verify_device = None

# Explicitly Define the Public API
__all__ = [
    "kyber_keygen", "kyber_encapsulate", "kyber_decapsulate",
    "falcon_keygen", "falcon_sign", "falcon_verify",
    "pq_xdh_handshake_mutual",
    "generate_mpc_key_shares", "reconstruct_secret",
    "secure_store_key", "retrieve_secure_key",
    "authenticate_with_mfa", "hybrid_key_exchange",
    "tpm_verify_device"
]
