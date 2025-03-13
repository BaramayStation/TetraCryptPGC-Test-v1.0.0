import os
import logging
from cryptography.hazmat.primitives.asymmetric import x25519, ec
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

# Define ML-KEM (Kyber-1024) KEM functions
ffi.cdef("""
    int OQS_KEM_mlkem_1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_KEM_mlkem_1024_encapsulate(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int OQS_KEM_mlkem_1024_decapsulate(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

MLKEM_PUBLICKEYBYTES = 1568
MLKEM_SECRETKEYBYTES = 3168
MLKEM_CIPHERTEXTBYTES = 1568
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

def derive_ecc_shared_secret(private_key, peer_public_key):
    """Derive a shared secret using ECC Diffie-Hellman with HKDF normalization."""
    shared_secret = private_key.exchange(peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit shared secret
        salt=None,
        info=b"TetraHybridPQ"
    )
    return hkdf.derive(shared_secret)

def mlkem_keygen():
    """Generate an ML-KEM-1024 key pair."""
    pk = ffi.new(f"unsigned char[{MLKEM_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{MLKEM_SECRETKEYBYTES}]")

    ret = oqs_lib.OQS_KEM_mlkem_1024_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError("ML-KEM key generation failed.")

    return bytes(pk), bytes(sk)

def mlkem_encapsulate(public_key):
    """Encapsulate a shared secret using ML-KEM-1024."""
    ct = ffi.new(f"unsigned char[{MLKEM_CIPHERTEXTBYTES}]")
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")

    ret = oqs_lib.OQS_KEM_mlkem_1024_encapsulate(ct, ss, public_key)
    if ret != 0:
        raise RuntimeError("ML-KEM encapsulation failed.")

    return bytes(ct), bytes(ss)

def mlkem_decapsulate(ciphertext, secret_key):
    """Decapsulate the shared secret using ML-KEM-1024."""
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")

    ret = oqs_lib.OQS_KEM_mlkem_1024_decapsulate(ss, ciphertext, secret_key)
    if ret != 0:
        raise RuntimeError("ML-KEM decapsulation failed.")

    return bytes(ss)

def hybrid_key_exchange():
    """Perform a hybrid key exchange using ECC (X25519) and ML-KEM-1024."""
    logging.info("[*] Generating ECC Key Pair...")
    ecc_private_key, ecc_public_key = generate_ecc_keypair("X25519")

    logging.info("[*] Generating ML-KEM Key Pair...")
    mlkem_public_key, mlkem_private_key = mlkem_keygen()

    logging.info("[*] Performing ECC Key Exchange...")
    shared_secret_ecc = derive_ecc_shared_secret(ecc_private_key, ecc_public_key)

    logging.info("[*] Performing ML-KEM Encapsulation...")
    mlkem_ciphertext, shared_secret_mlkem = mlkem_encapsulate(mlkem_public_key)

    logging.info("[*] Hybrid Key Exchange Completed.")

    return {
        "ecc_public_key": ecc_public_key.public_bytes_raw().hex(),
        "mlkem_public_key": mlkem_public_key.hex(),
        "shared_secret_ecc": shared_secret_ecc.hex(),
        "shared_secret_mlkem": shared_secret_mlkem.hex()
    }

# Example Usage
if __name__ == "__main__":
    try:
        keys = hybrid_key_exchange()
        logging.info(f"Generated Hybrid Keys: {keys}")
        print("Hybrid PQC + ECC Key Exchange Successful ✅")
    except Exception as e:
        logging.error(f"Error: {e}")
