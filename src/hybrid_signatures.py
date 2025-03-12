import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
from src.falcon_sign import falcon_sign, falcon_verify

# ---------------- Hybrid Signature (Dilithium + Falcon) ----------------

def hybrid_generate_signatures(message):
    """Sign a message using Dilithium (PQC) + Falcon (PQC)."""

    # Generate Falcon Keys
    falcon_pk, falcon_sk = falcon_keygen()

    # Generate Dilithium Keys
    dilithium_pk, dilithium_sk = generate_keypair()

    # Falcon Signature
    falcon_sig = falcon_sign(message, falcon_sk)

    # Dilithium Signature
    dilithium_sig = sign(message, dilithium_sk)

    return falcon_sig, falcon_pk, dilithium_sig, dilithium_pk

def hybrid_verify_signatures(message, falcon_sig, falcon_pk, dilithium_sig, dilithium_pk):
    """Verify both Dilithium & Falcon signatures."""

    # Verify Falcon
    falcon_valid = falcon_verify(message, falcon_sig, falcon_pk)

    # Verify Dilithium
    dilithium_valid = verify(message, dilithium_sig, dilithium_pk)

    return falcon_valid and dilithium_valid

if __name__ == "__main__":
    message = b"Hybrid Post-Quantum Authentication"
    falcon_sig, falcon_pk, dilithium_sig, dilithium_pk = hybrid_generate_signatures(message)
    valid = hybrid_verify_signatures(message, falcon_sig, falcon_pk, dilithium_sig, dilithium_pk)

    print(f"Hybrid Signature Verification Successful: {valid}")
