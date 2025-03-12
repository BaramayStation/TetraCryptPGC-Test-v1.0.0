import os
import secrets
from cffi import FFI
from cryptography.hazmat.primitives.asymmetric import x25519
from secure_hsm import store_key_in_hsm, retrieve_key_from_hsm

# Example: Generating a nonce
nonce = secrets.token_bytes(32)

def generate_secure_kyber_keys():
    """Generate a Kyber keypair and store it in HSM."""
    from src.kyber_kem import kyber_keygen  # Lazy import to prevent circular import issue
    pk, sk = kyber_keygen()
    store_key_in_hsm(sk)  # Store Kyber Secret Key inside HSM
    return pk, sk

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
    print("[*] Generating ECC Key Pair...")
    ecc_private_key, ecc_public_key = ecc_keygen()

    print("[*] Generating Kyber Key Pair...")
    kyber_public_key, kyber_private_key = generate_secure_kyber_keys()

    print("[*] Performing X25519 Key Exchange...")
    shared_secret = ecc_key_exchange(ecc_private_key, ecc_public_key)  # Self-exchange for test

    print("[*] Hybrid Key Exchange Completed.")
    return {
        "ecc_public_key": ecc_public_key.public_bytes_raw().hex(),
        "kyber_public_key": kyber_public_key.hex(),
        "shared_secret": shared_secret.hex()
    }

# If this file is run directly, perform hybrid key exchange
if __name__ == "__main__":
    keys = hybrid_key_exchange()
    print("Generated Keys:", keys)

ffi = FFI()
KYBER_LIB_PATH = os.getenv("KYBER_LIB_PATH", "/app/lib/libpqclean_kyber1024_clean.so")
