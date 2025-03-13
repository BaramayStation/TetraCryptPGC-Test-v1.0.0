import os
import secrets
import logging
from cffi import FFI
from cryptography.hazmat.primitives.asymmetric import x25519
from secure_hsm import store_key_in_hsm, retrieve_key_from_hsm

# Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Set the environment variable for KYBER_LIB_PATH to point to the appropriate library
KYBER_LIB_PATH = os.getenv("KYBER_LIB_PATH", "/app/lib/liboqs.so")

# Initialize FFI (Foreign Function Interface)
ffi = FFI()

# Check if the specified library exists before attempting to load it
try:
    kyber_lib = ffi.dlopen(KYBER_LIB_PATH)
except Exception as e:
    raise RuntimeError(f"Could not load Kyber library from {KYBER_LIB_PATH}: {e}")

# Define the Kyber KEM functions using liboqs
ffi.cdef("""
    int OQS_KEM_KYBER1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_KEM_KYBER1024_encapsulate(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int OQS_KEM_KYBER1024_decapsulate(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

# Function for generating Kyber keypair and storing it in HSM
def generate_secure_kyber_keys():
    """Generate a Kyber keypair and store it in HSM."""
    pk = ffi.new("unsigned char[1568]")  # Kyber public key size
    sk = ffi.new("unsigned char[3168]")  # Kyber secret key size

    # Generate Kyber keypair using liboqs (replace this with the function call for your selected library)
    ret = kyber_lib.OQS_KEM_KYBER1024_keypair(pk, sk)
    if ret != 0:
        raise ValueError("Kyber key generation failed.")

    store_key_in_hsm(sk)  # Store Kyber Secret Key inside HSM

    return bytes(pk), bytes(sk)

# ECC (Elliptic Curve Cryptography) key generation and exchange using X25519
def ecc_keygen():
    """Generate an X25519 key pair for hybrid key exchange."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def ecc_key_exchange(private_key, peer_public_key):
    """Perform X25519 key exchange."""
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

def hybrid_key_exchange():
    """Perform hybrid key exchange using Kyber + X25519."""
    logging.info("[*] Generating ECC Key Pair...")
    ecc_private_key, ecc_public_key = ecc_keygen()

    logging.info("[*] Generating Kyber Key Pair...")
    kyber_public_key, kyber_private_key = generate_secure_kyber_keys()

    logging.info("[*] Performing X25519 Key Exchange...")
    shared_secret = ecc_key_exchange(ecc_private_key, ecc_public_key)  # Self-exchange for test

    logging.info("[*] Hybrid Key Exchange Completed.")
    return {
        "ecc_public_key": ecc_public_key.public_bytes_raw().hex(),
        "kyber_public_key": kyber_public_key.hex(),
        "shared_secret": shared_secret.hex()
    }

# If this file is run directly, perform hybrid key exchange
if __name__ == "__main__":
    keys = hybrid_key_exchange()
    logging.info(f"Generated Keys: {keys}")