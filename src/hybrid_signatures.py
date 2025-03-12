import os
import hashlib
import logging
from cryptography.hazmat.primitives.asymmetric import ed25519
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

# ---------------- Hybrid Signature (Dilithium + Falcon) ----------------

def hybrid_generate_signatures(message):
    """Sign a message using Dilithium (PQC) + Falcon (PQC)."""

    # Step 1: Generate Falcon Key Pair
    falcon_pk, falcon_sk = falcon_keygen()

    # Step 2: Generate Dilithium Key Pair
    dilithium_pk, dilithium_sk = generate_keypair()

    # Step 3: Falcon Signature
    falcon_sig = falcon_sign(message, falcon_sk)

    # Step 4: Dilithium Signature
    dilithium_sig = sign(message, dilithium_sk)

    logging.info("[✔] Hybrid Signature Generation Complete")
    return {
        "falcon_sig": falcon_sig,
        "falcon_pk": falcon_pk,
        "dilithium_sig": dilithium_sig,
        "dilithium_pk": dilithium_pk
    }

def hybrid_verify_signatures(message, signatures):
    """Verify both Dilithium & Falcon signatures."""

    falcon_valid = falcon_verify(message, signatures["falcon_sig"], signatures["falcon_pk"])
    dilithium_valid = verify(message, signatures["dilithium_sig"], signatures["dilithium_pk"])

    if not falcon_valid:
        logging.warning("[❌] Falcon Signature Verification Failed")

    if not dilithium_valid:
        logging.warning("[❌] Dilithium Signature Verification Failed")

    return falcon_valid and dilithium_valid

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    message = b"Hybrid Post-Quantum Authentication"
    signatures = hybrid_generate_signatures(message)
    valid = hybrid_verify_signatures(message, signatures)

    print(f"✅ Hybrid Signature Verification Successful: {valid}")
