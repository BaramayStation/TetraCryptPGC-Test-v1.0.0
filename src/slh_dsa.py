import os
import logging
import hashlib
import ctypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

# ✅ Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ✅ Load SLH-DSA Library
SLH_DSA_PATH = os.getenv("SLH_DSA_PATH", "/usr/local/lib/libslh_dsa.so")

try:
    slh_dsa_lib = ctypes.CDLL(SLH_DSA_PATH)
    logging.info("✅ SLH-DSA Library Loaded Successfully!")
except Exception as e:
    logging.error(f"❌ Failed to load SLH-DSA Library: {e}")
    raise RuntimeError("SLH-DSA library missing or incorrectly installed.")

class SLHDSA:
    """Implements SLH-DSA (FIPS 205) for post-quantum digital signatures."""

    @staticmethod
    def generate_keypair():
        """Generate an SLH-DSA key pair."""
        public_key = ctypes.create_string_buffer(64)
        private_key = ctypes.create_string_buffer(128)

        ret = slh_dsa_lib.slh_dsa_keygen(public_key, private_key)
        if ret != 0:
            raise RuntimeError("SLH-DSA key generation failed.")

        return public_key.raw, private_key.raw

    @staticmethod
    def sign_message(message, private_key):
        """Sign a message using SLH-DSA."""
        signature = ctypes.create_string_buffer(64)
        message_hash = hashlib.sha3_512(message).digest()

        ret = slh_dsa_lib.slh_dsa_sign(signature, message_hash, private_key)
        if ret != 0:
            raise RuntimeError("SLH-DSA signing failed.")

        return signature.raw

    @staticmethod
    def verify_signature(message, signature, public_key):
        """Verify an SLH-DSA signature."""
        message_hash = hashlib.sha3_512(message).digest()

        ret = slh_dsa_lib.slh_dsa_verify(signature, message_hash, public_key)
        return ret == 0  # 0 means verification successful

# ✅ Example Execution
if __name__ == "__main__":
    logging.info("🔹 Testing SLH-DSA Digital Signatures...")

    # Generate Keypair
    pub_key, priv_key = SLHDSA.generate_keypair()
    logging.info(f"✅ SLH-DSA Public Key: {pub_key.hex()}")

    # Sign a Message
    message = b"TetraCrypt Secure Signature Test"
    signature = SLHDSA.sign_message(message, priv_key)
    logging.info(f"✅ SLH-DSA Signature: {signature.hex()}")

    # Verify Signature
    if SLHDSA.verify_signature(message, signature, pub_key):
        logging.info("✅ SLH-DSA Signature Verification Successful!")
    else:
        logging.error("❌ SLH-DSA Signature Verification Failed!")
