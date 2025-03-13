import os
import logging
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cffi import FFI

# Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load liboqs for post-quantum hybrid key exchange
LIBOQS_PATH = os.getenv("LIBOQS_PATH", "/usr/local/lib/liboqs.so")
ffi = FFI()

try:
    oqs_lib = ffi.dlopen(LIBOQS_PATH)
    logging.info("liboqs successfully loaded for hybrid key exchange.")
except Exception as e:
    logging.error(f"Could not load liboqs: {e}")
    raise RuntimeError("liboqs missing or not installed.")

# Define Kyber KEM functions for hybrid mode
ffi.cdef("""
    int OQS_KEM_KYBER1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_KEM_KYBER1024_encapsulate(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int OQS_KEM_KYBER1024_decapsulate(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

KYBER_PUBLICKEYBYTES = 1568
KYBER_SECRETKEYBYTES = 3168
KYBER_CIPHERTEXTBYTES = 1568
SHARED_SECRET_BYTES = 32

def generate_ecc_keypair(curve="X25519"):
    """Generate an ECC key pair (X25519 or P-384)."""
    if curve == "X25519":
        private_key = x25519.X25519PrivateKey.generate()
    elif curve == "P-384":
        private_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError("Unsupported curve. Choose 'X25519' or 'P-384'.")
    
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    """Convert a public key to bytes for transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    """Convert bytes back to a public key object."""
    return serialization.load_pem_public_key(public_key_bytes)

def derive_ecc_shared_secret(private_key, peer_public_key):
    """Derive a shared secret using ECC Diffie-Hellman with HKDF normalization."""
    if isinstance(peer_public_key, bytes):
        peer_public_key = deserialize_public_key(peer_public_key)

    shared_secret = private_key.exchange(peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit shared secret
        salt=None,
        info=b"TetraHybridPQ"
    )
    return hkdf.derive(shared_secret)

def kyber_keygen():
    """Generate a Kyber-1024 key pair."""
    pk = ffi.new(f"unsigned char[{KYBER_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{KYBER_SECRETKEYBYTES}]")

    ret = oqs_lib.OQS_KEM_KYBER1024_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError("Kyber key generation failed.")

    return bytes(pk), bytes(sk)

def kyber_encapsulate(public_key):
    """Encapsulate a shared secret using Kyber-1024."""
    ct = ffi.new(f"unsigned char[{KYBER_CIPHERTEXTBYTES}]")
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")

    ret = oqs_lib.OQS_KEM_KYBER1024_encapsulate(ct, ss, public_key)
    if ret != 0:
        raise RuntimeError("Kyber encapsulation failed.")

    return bytes(ct), bytes(ss)

def kyber_decapsulate(ciphertext, secret_key):
    """Decapsulate the shared secret using Kyber-1024."""
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")

    ret = oqs_lib.OQS_KEM_KYBER1024_decapsulate(ss, ciphertext, secret_key)
    if ret != 0:
        raise RuntimeError("Kyber decapsulation failed.")

    return bytes(ss)

def hybrid_key_exchange():
    """Perform a hybrid key exchange using ECC (X25519) and Kyber-1024."""
    logging.info("[*] Generating ECC Key Pair...")
    ecc_private_key, ecc_public_key = generate_ecc_keypair("X25519")

    logging.info("[*] Generating Kyber Key Pair...")
    kyber_public_key, _ = kyber_keygen()  # Only public key is used, so private key is ignored.

    logging.info("[*] Performing ECC Key Exchange...")
    shared_secret_ecc = derive_ecc_shared_secret(ecc_private_key, ecc_public_key)

    logging.info("[*] Performing Kyber Encapsulation...")
    _, shared_secret_kyber = kyber_encapsulate(kyber_public_key)  # Replace unused variable with _

    logging.info("[*] Hybrid Key Exchange Completed.")

    return {
        "ecc_public_key": ecc_public_key.public_bytes_raw().hex(),
        "kyber_public_key": kyber_public_key.hex(),
        "shared_secret_ecc": shared_secret_ecc.hex(),
        "shared_secret_kyber": shared_secret_kyber.hex()
    }

# Example Usage
if __name__ == "__main__":
    try:
        keys = hybrid_key_exchange()
        logging.info(f"Generated Hybrid Keys: {keys}")
        print("Hybrid PQC + ECC Key Exchange Successful ✅")
    except Exception as e:
        logging.error(f"Error: {e}")
