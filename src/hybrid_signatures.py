import os
import logging
from hashlib import sha3_512
from cryptography.hazmat.primitives.asymmetric import ed25519
from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

# 🔹 Secure Logging for Signature Authentication
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def hybrid_generate_signatures(message):
    """Sign a message using Dilithium (PQC) + Falcon (PQC)."""

    logging.info("🔹 Generating Falcon Key Pair...")
    falcon_pk, falcon_sk = falcon_keygen()

    logging.info("🔹 Generating Dilithium Key Pair...")
    dilithium_pk, dilithium_sk = generate_keypair()

    logging.info("🔹 Signing Message with Falcon-1024...")
    falcon_sig = falcon_sign(message, falcon_sk)

    logging.info("🔹 Signing Message with Dilithium-3...")
    dilithium_sig = sign(message, dilithium_sk)

    logging.info("✅ Hybrid Signature Generation Complete")
    return {
        "falcon_sig": falcon_sig,
        "falcon_pk": falcon_pk,
        "dilithium_sig": dilithium_sig,
        "dilithium_pk": dilithium_pk
    }


def hybrid_verify_signatures(message, signatures):
    """Verify both Dilithium & Falcon signatures."""

    logging.info("🔹 Verifying Falcon Signature...")
    falcon_valid = falcon_verify(message, signatures["falcon_sig"], signatures["falcon_pk"])
    if not falcon_valid:
        logging.warning("⚠️ Falcon Signature Verification Failed!")

    logging.info("🔹 Verifying Dilithium Signature...")
    dilithium_valid = verify(message, signatures["dilithium_sig"], signatures["dilithium_pk"])
    if not dilithium_valid:
        logging.warning("⚠️ Dilithium Signature Verification Failed!")

    if falcon_valid and dilithium_valid:
        logging.info("✅ Hybrid Signature Verification Successful.")
        return True
    else:
        logging.error("❌ One or more signature verifications failed.")
        return False


# 🔹 Example Execution for Hybrid PQC Digital Signatures
if __name__ == "__main__":
    message = b"Hybrid Post-Quantum Authentication"

    logging.info("🔹 Generating Hybrid Signatures...")
    signatures = hybrid_generate_signatures(message)

    logging.info("🔹 Verifying Hybrid Signatures...")
    valid = hybrid_verify_signatures(message, signatures)

    print(f"\n🔑 Hybrid Signature Verification Status: {'✅ Valid' if valid else '❌ Invalid'}")