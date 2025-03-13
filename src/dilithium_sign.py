import os
import logging
from cffi import FFI

# Initialize FFI (Foreign Function Interface)
ffi = FFI()

# Set up logging for security monitoring
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Locate and load the liboqs shared library
LIBOQS_PATH = os.getenv("LIBOQS_PATH", "/usr/local/lib/liboqs.so")

try:
    dilithium_lib = ffi.dlopen(LIBOQS_PATH)
    logging.info("liboqs (Dilithium-3) successfully loaded.")
except Exception as e:
    logging.error(f"Could not load liboqs library: {e}")
    raise RuntimeError("liboqs missing or not installed.")

# Define the function signatures for Dilithium-3
ffi.cdef("""
    int OQS_SIG_dilithium_3_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_SIG_dilithium_3_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
    int OQS_SIG_dilithium_3_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
""")

# Set the key and signature sizes for Dilithium-3
DILITHIUM_PUBLICKEYBYTES = 1952
DILITHIUM_SECRETKEYBYTES = 4000
DILITHIUM_SIGNATUREBYTES = 3293

def dilithium_keygen():
    """Generate a secure Dilithium-3 key pair."""
    pk = ffi.new(f"unsigned char[{DILITHIUM_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{DILITHIUM_SECRETKEYBYTES}]")

    # Generate the key pair using liboqs
    ret = dilithium_lib.OQS_SIG_dilithium_3_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError("Dilithium-3 key generation failed.")

    return bytes(pk), bytes(sk)

def dilithium_sign(message, secret_key):
    """Sign a message securely using Dilithium-3."""
    if not isinstance(message, bytes):
        message = message.encode("utf-8")  # Convert to bytes

    sig = ffi.new(f"unsigned char[{DILITHIUM_SIGNATUREBYTES}]")
    siglen = ffi.new("size_t *")

    ret = dilithium_lib.OQS_SIG_dilithium_3_sign(sig, siglen, message, len(message), secret_key)
    if ret != 0:
        raise RuntimeError("Dilithium-3 signing failed.")

    return bytes(sig)[:siglen[0]]

def dilithium_verify(message, signature, public_key):
    """Verify a Dilithium-3 signature and return a boolean result."""
    if not isinstance(message, bytes):
        message = message.encode("utf-8")  # Convert to bytes

    ret = dilithium_lib.OQS_SIG_dilithium_3_verify(signature, len(signature), message, len(message), public_key)
    return ret == 0  # Returns True if valid, False if invalid

# Example Usage
if __name__ == "__main__":
    try:
        logging.info("Generating Dilithium-3 key pair...")
        pub_key, priv_key = dilithium_keygen()

        message = "This is a secure post-quantum message."
        logging.info("Signing message...")

        signature = dilithium_sign(message, priv_key)
        logging.info(f"Signature: {signature.hex()}")

        logging.info("Verifying signature...")
        is_valid = dilithium_verify(message, signature, pub_key)

        if is_valid:
            logging.info("✅ Signature Verification: Valid")
        else:
            logging.error("❌ Signature Verification: Invalid")

    except Exception as e:
        logging.error(f"Error: {e}")