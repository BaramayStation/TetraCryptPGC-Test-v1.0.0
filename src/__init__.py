"""
TetraCryptPGC: Post-Quantum Cryptography Toolkit

This package implements a post-quantum secure XDH handshake using:
- **Kyber-1024** (Key Encapsulation Mechanism)
- **Falcon-1024** (Digital Signatures)
- **Hybrid Key Derivation (HKDF)**
- **Secure Enclave Support (SGX, TPM)**
- **Multi-Factor Authentication (MFA)** (Optional)

Complies with NIST post-quantum cryptography standards.
"""

__version__ = "1.0.0"
__author__ = "Abraxas618"
__license__ = "MIT"

# Lazy Imports (Optimized for Performance)
from importlib import import_module

# Kyber KEM (Key Exchange)
kyber = import_module("src.kyber_kem")
kyber_keygen = kyber.kyber_keygen
kyber_encapsulate = kyber.kyber_encapsulate
kyber_decapsulate = kyber.kyber_decapsulate

# Falcon Signatures
falcon = import_module("src.falcon_sign")
falcon_keygen = falcon.falcon_keygen
falcon_sign = falcon.falcon_sign
falcon_verify = falcon.falcon_verify

# Post-Quantum Mutual Authentication Handshake
handshake = import_module("src.handshake")
pq_xdh_handshake_mutual = handshake.pq_xdh_handshake_mutual

# Optional Secure Enclave & MFA (Ensure Dependencies Exist)
try:
    enclave = import_module("src.secure_enclave")
    secure_store_key = enclave.secure_store_key
    retrieve_secure_key = enclave.retrieve_secure_key
except ImportError:
    secure_store_key = None
    retrieve_secure_key = None

try:
    mfa = import_module("src.mfa_auth")
    authenticate_with_mfa = mfa.authenticate_with_mfa
except ImportError:
    authenticate_with_mfa = None

__all__ = [
    'kyber_keygen', 'kyber_encapsulate', 'kyber_decapsulate',
    'falcon_keygen', 'falcon_sign', 'falcon_verify',
    'pq_xdh_handshake_mutual', 
    'secure_store_key', 'retrieve_secure_key',
    'authenticate_with_mfa'
]
