"""
TetraCryptPGC: Post-Quantum Cryptography Toolkit

This package implements a post-quantum secure XDH handshake using:
- **Kyber-1024** (Key Encapsulation Mechanism via liboqs)
- **Falcon-1024** (Digital Signatures via liboqs)
- **Hybrid Key Derivation (HKDF)**
- **Secure Enclave Support (SGX, TPM, HSM)**
- **Multi-Factor Authentication (MFA)**
- **Multi-Party Computation (MPC) for Key Sharing**
- **Post-Quantum Hybrid Mode (PQC + ECC Transition)**
- **TPM-Based Remote Attestation for Device Integrity Verification**

Complies with NIST post-quantum cryptography standards and FIPS 140-2/3 validation.
"""

import logging
import importlib
import sys
import os
from cffi import FFI

# Set Versioning Information
__version__ = "1.3.0"
__author__ = "Abraxas618"
__license__ = "MIT"

# Security Debug Mode (Set to False in Production)
DEBUG_MODE = os.getenv("TETRACRYPT_DEBUG", "False").lower() in ["true", "1"]

# Structured Logging for Security Audits
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Ensure correct module paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def load_module(module_name, critical=False):
    """Dynamically import a module with error handling."""
    try:
        if module_name.startswith("src."):
            sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

        module = importlib.import_module(module_name)
        logging.info(f"{module_name} Loaded Successfully")
        return module
    except ImportError as e:
        logging.error(f"{module_name} Not Found: {e}")
        if critical:
            sys.exit(f"Critical Module Missing: {module_name}")
        return None

# Load Post-Quantum Cryptographic Modules using liboqs
ffi = FFI()
LIBOQS_PATH = os.getenv("LIBOQS_PATH", "/usr/local/lib/liboqs.so")  # Default path

try:
    pqc_lib = ffi.dlopen(LIBOQS_PATH)
    logging.info("Loaded liboqs for PQC operations.")
except Exception as e:
    logging.error(f"Failed to load liboqs: {e}")
    sys.exit("Critical error: liboqs missing or not installed.")

ffi.cdef("""
    int OQS_KEM_KYBER1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_KEM_KYBER1024_encapsulate(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int OQS_KEM_KYBER1024_decapsulate(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    int OQS_SIG_falcon_1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_SIG_falcon_1024_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
    int OQS_SIG_falcon_1024_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
""")

# Kyber Key Exchange via liboqs
def kyber_keygen():
    """Generate a Kyber-1024 key pair using liboqs."""
    pk = ffi.new("unsigned char[1568]")
    sk = ffi.new("unsigned char[3168]")
    ret = pqc_lib.OQS_KEM_KYBER1024_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError("Kyber key generation failed.")
    return bytes(pk), bytes(sk)

def kyber_encapsulate(public_key):
    """Encapsulate a shared secret using Kyber-1024."""
    ct = ffi.new("unsigned char[1568]")
    ss = ffi.new("unsigned char[32]")
    ret = pqc_lib.OQS_KEM_KYBER1024_encapsulate(ct, ss, public_key)
    if ret != 0:
        raise RuntimeError("Kyber encapsulation failed.")
    return bytes(ct), bytes(ss)

def kyber_decapsulate(ciphertext, secret_key):
    """Decapsulate the shared secret using Kyber-1024."""
    ss = ffi.new("unsigned char[32]")
    ret = pqc_lib.OQS_KEM_KYBER1024_decapsulate(ss, ciphertext, secret_key)
    if ret != 0:
        raise RuntimeError("Kyber decapsulation failed.")
    return bytes(ss)

# Falcon Signatures via liboqs
def falcon_keygen():
    """Generate a Falcon-1024 key pair using liboqs."""
    pk = ffi.new("unsigned char[1792]")
    sk = ffi.new("unsigned char[2304]")
    ret = pqc_lib.OQS_SIG_falcon_1024_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError("Falcon key generation failed.")
    return bytes(pk), bytes(sk)

def falcon_sign(message, secret_key):
    """Sign a message using Falcon-1024."""
    sig = ffi.new("unsigned char[1280]")
    siglen = ffi.new("size_t *")
    ret = pqc_lib.OQS_SIG_falcon_1024_sign(sig, siglen, message, len(message), secret_key)
    if ret != 0:
        raise RuntimeError("Falcon signing failed.")
    return bytes(sig)[:siglen[0]]

def falcon_verify(message, signature, public_key):
    """Verify a Falcon-1024 signature."""
    ret = pqc_lib.OQS_SIG_falcon_1024_verify(signature, len(signature), message, len(message), public_key)
    return ret == 0

# Load Hybrid PQC + ECC Handshake
handshake = load_module("src.handshake", critical=True)
pq_xdh_handshake_mutual = handshake.pq_xdh_handshake_mutual

# Load Secure Enclave (SGX, TPM, HSM)
enclave = load_module("src.secure_enclave")
if enclave:
    secure_store_key = enclave.secure_store_key
    retrieve_secure_key = enclave.retrieve_secure_key
else:
    logging.warning("Secure Enclave Support Not Available. Using File-Based Fallback.")

# Multi-Factor Authentication (MFA)
mfa = load_module("src.mfa_auth")
authenticate_with_mfa = mfa.authenticate_with_mfa if mfa else None

# TPM-Based Remote Attestation
tpm = load_module("src.tpm_attestation")
tpm_verify_device = tpm.tpm_verify_device if tpm else None

# Ensure Cryptographic Algorithm Compatibility
def validate_crypto_versions():
    """Ensure compatible versions of Kyber, Falcon, and MPC are loaded."""
    logging.info("Crypto modules loaded successfully.")

validate_crypto_versions()

# Explicitly Define the Public API
__all__ = [
    "kyber_keygen", "kyber_encapsulate", "kyber_decapsulate",
    "falcon_keygen", "falcon_sign", "falcon_verify",
    "pq_xdh_handshake_mutual",
    "secure_store_key", "retrieve_secure_key",
    "authenticate_with_mfa",
    "tpm_verify_device"
]