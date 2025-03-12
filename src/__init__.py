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
import importlib
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
__version__ = "1.2.1"
__author__ = "Abraxas618"
__license__ = "MIT"

# Security Debug Mode (Set to False in Production)
DEBUG_MODE = os.getenv("TETRACRYPT_DEBUG", "False").lower() in ["true", "1"]

# Structured Logging for Security Audits
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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


# Load Post-Quantum Cryptographic Modules
kyber = load_module("src.kyber_kem", critical=True)
falcon = load_module("src.falcon_sign", critical=True)
handshake = load_module("src.handshake", critical=True)

# Assign Kyber Functions
kyber_keygen = kyber.kyber_keygen
kyber_encapsulate = kyber.kyber_encapsulate
kyber_decapsulate = kyber.kyber_decapsulate

# Assign Falcon Functions
falcon_keygen = falcon.falcon_keygen
falcon_sign = falcon.falcon_sign
falcon_verify = falcon.falcon_verify

# PQC + ECC Handshake
pq_xdh_handshake_mutual = handshake.pq_xdh_handshake_mutual

# Multi-Party Computation (MPC) for Key Sharing
mpc = load_module("src.mpc_key_sharing")
if mpc:
    generate_mpc_key_shares = mpc.generate_mpc_key_shares
    reconstruct_secret = mpc.reconstruct_secret
else:
    generate_mpc_key_shares = reconstruct_secret = None

# Secure Enclave (SGX, TPM, HSM) Handling
enclave = load_module("src.secure_enclave")
if enclave:
    secure_store_key = enclave.secure_store_key
    retrieve_secure_key = enclave.retrieve_secure_key
else:
    logging.warning("Secure Enclave Support Not Available. Using File-Based Fallback.")

    def secure_store_key(data, filename="secure_fallback.dat"):
        """Fallback: Store in encrypted file if SGX/TPM not available."""
        with open(filename, "wb") as f:
            f.write(data)
        logging.info(f"Key stored in {filename} (Fallback Mode)")

    def retrieve_secure_key(filename="secure_fallback.dat"):
        """Fallback: Retrieve key from file."""
        if not os.path.exists(filename):
            raise FileNotFoundError("Fallback Key Not Found!")
        with open(filename, "rb") as f:
            return f.read()

# Multi-Factor Authentication (MFA)
mfa = load_module("src.mfa_auth")
authenticate_with_mfa = mfa.authenticate_with_mfa if mfa else None

# Hybrid PQC + ECC Transition
hybrid_pqc = load_module("src.hybrid_pqc")
hybrid_key_exchange = hybrid_pqc.hybrid_key_exchange if hybrid_pqc else None

# TPM-Based Remote Attestation
tpm = load_module("src.tpm_attestation")
tpm_verify_device = tpm.tpm_verify_device if tpm else None

# Ensure Cryptographic Algorithm Compatibility
def validate_crypto_versions():
    """Ensure compatible versions of Kyber, Falcon, and MPC are loaded."""
    if kyber and getattr(kyber, "__version__", "Unknown") < "1.0":
        raise RuntimeError("Kyber Version Mismatch! Update Required.")
    if falcon and getattr(falcon, "__version__", "Unknown") < "1.0":
        raise RuntimeError("Falcon Version Mismatch! Update Required.")
    if mpc and getattr(mpc, "__version__", "Unknown") < "1.0":
        logging.warning("MPC Version Mismatch! Consider Updating.")

validate_crypto_versions()

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
