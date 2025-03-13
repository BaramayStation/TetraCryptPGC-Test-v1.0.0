import os
import logging
import secrets
from cffi import FFI
from hashlib import sha256

# ✅ Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ✅ Load SLH-DSA Library
SLH_DSA_LIB_PATH = os.getenv("SLH_DSA_LIB_PATH", "/usr/local/lib/libslh-dsa.so")
ffi = FFI()

try:
    slh_dsa_lib = ffi.dlopen(SLH_DSA_LIB_PATH)
    logging.info("[✔] SLH-DSA library successfully loaded.")
except Exception as e:
    logging.error(f"[ERROR] Could not load SLH-DSA library: {e}")
    raise RuntimeError("SLH-DSA library missing or not installed.")

# ✅ Define SLH-DSA C Bindings
ffi.cdef("""
    int slh_dsa_keygen(unsigned char *pk, unsigned char *sk);
    int slh_dsa_sign(unsigned char *sig, const unsigned char *msg, size_t msg_len, const unsigned char *sk);
    int slh_dsa_verify(const unsigned char *sig, const unsigned char *msg, size_t msg_len, const unsigned char *pk);
""")

SLH_DSA_PUBLICKEYBYTES = 64
SLH_DSA_SECRETKEYBYTES = 128
SLH_DSA_SIGNATUREBYTES = 96

class SLH_DSA:
    """Implements FIPS 205 SLH-DSA for Stateless Hash-based Signatures."""

    @staticmethod
    def generate_keypair():
        """Generate an SLH-DSA key pair."""
        pk = ffi.new(f"unsigned char[{SLH_DSA_PUBLICKEYBYTES}]")
        sk = ffi.new(f"unsigned char[{SLH_DSA_SECRETKEYBYTES}]")

        ret = slh_dsa_lib.slh_dsa_keygen(pk, sk)
        if ret != 0:
            raise RuntimeError("SLH-DSA key generation failed.")

        return bytes(pk), bytes(sk)

    @staticmethod
    def sign_message(message, private_key):
        """Sign a message using SLH-DSA."""
        sig = ffi.new(f"unsigned char[{SLH_DSA_SIGNATUREBYTES}]")
        msg_bytes = message.encode() if isinstance(message, str) else message

        ret = slh_dsa_lib.slh_dsa_sign(sig, msg_bytes, len(msg_bytes), private_key)
        if ret != 0:
            raise RuntimeError("SLH-DSA signing failed.")

        return bytes(sig)

    @staticmethod
    def verify_signature(signature, message, public_key):
        """Verify an SLH-DSA signature."""
        msg_bytes = message.encode() if isinstance(message, str) else message

        ret = slh_dsa_lib.slh_dsa_verify(signature, msg_bytes, len(msg_bytes), public_key)
        return ret == 0  # ✅ Returns True if valid, False if invalid

# ✅ Example Usage
if __name__ == "__main__":
    logging.info("🔹 Testing SLH-DSA Implementation...")

    pk, sk = SLH_DSA.generate_keypair()
    logging.info(f"🔑 Public Key: {pk.hex()}")
    logging.info(f"🔒 Secret Key: {sk.hex()}")

    message = "TetraCrypt Secure Message"
    signature = SLH_DSA.sign_message(message, sk)

    if SLH_DSA.verify_signature(signature, message, pk):
        logging.info("[✔] SLH-DSA Signature Verification Passed!")
    else:
        logging.error("[❌] SLH-DSA Signature Verification Failed!")
