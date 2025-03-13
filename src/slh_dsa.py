import os
import logging
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cffi import FFI

# Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load PQClean's XMSS Implementation
PQ_CLEAN_LIB_PATH = os.getenv("PQ_CLEAN_LIB_PATH", "/usr/local/lib/libpqclean_xmss.so")
ffi = FFI()

try:
    pqclean_lib = ffi.dlopen(PQ_CLEAN_LIB_PATH)
    logging.info("PQClean XMSS library loaded successfully.")
except Exception as e:
    logging.error(f"Could not load PQClean XMSS: {e}")
    raise RuntimeError("PQClean XMSS missing or not installed.")

# Define XMSS Signing Functions from PQClean
ffi.cdef("""
    int PQCLEAN_XMSS_keypair(unsigned char *pk, unsigned char *sk);
    int PQCLEAN_XMSS_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
    int PQCLEAN_XMSS_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
""")

XMSS_PUBLICKEYBYTES = 132
XMSS_SECRETKEYBYTES = 256
XMSS_SIGNATUREBYTES = 2500

def slh_dsa_keygen():
    """Generate an XMSS key pair for SLH-DSA (FIPS 205)."""
    pk = ffi.new(f"unsigned char[{XMSS_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{XMSS_SECRETKEYBYTES}]")

    ret = pqclean_lib.PQCLEAN_XMSS_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError("XMSS key generation failed.")

    logging.info("[✔] XMSS Key Pair generated.")
    return bytes(pk), bytes(sk)

def slh_dsa_sign(message, secret_key):
    """Sign a message using XMSS (SLH-DSA)."""
    sig = ffi.new(f"unsigned char[{XMSS_SIGNATUREBYTES}]")
    siglen = ffi.new("size_t *")

    ret = pqclean_lib.PQCLEAN_XMSS_sign(sig, siglen, message, len(message), secret_key)
    if ret != 0:
        raise RuntimeError("XMSS signing failed.")

    logging.info("[✔] Message signed successfully using XMSS (SLH-DSA).")
    return bytes(sig)

def slh_dsa_verify(message, signature, public_key):
    """Verify an XMSS (SLH-DSA) signature."""
    ret = pqclean_lib.PQCLEAN_XMSS_verify(signature, len(signature), message, len(message), public_key)

    if ret == 0:
        logging.info("[✔] XMSS Signature verified successfully.")
        return True
    else:
        logging.error("[❌] XMSS Signature verification failed!")
        return False

# Example Usage
if __name__ == "__main__":
    message = b"Post-Quantum Secure Message"
    
    pk, sk = slh_dsa_keygen()
    signature = slh_dsa_sign(message, sk)

    if slh_dsa_verify(message, signature, pk):
        print("✅ SLH-DSA Signature Verified!")
    else:
        print("❌ SLH-DSA Signature Verification Failed!")
