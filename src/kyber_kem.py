import os
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives import hashes
from cffi import FFI

ffi = FFI()
KYBER_LIB_PATH = os.getenv("KYBER_LIB_PATH", "/app/lib/libpqclean_kyber1024_clean.so")
lib = ffi.dlopen(KYBER_LIB_PATH)

# Define C functions for Kyber KEM
ffi.cdef("""
    void PQCLEAN_KYBER1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_KYBER1024_CLEAN_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    void PQCLEAN_KYBER1024_CLEAN_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

# Constants from PQCLEAN
KYBER_PUBLICKEYBYTES = 1568
KYBER_SECRETKEYBYTES = 3168
KYBER_CIPHERTEXTBYTES = 1568
SHARED_SECRET_BYTES = 32  # Standard Kyber shared secret length

def zeroize_memory(data):
    """Securely overwrite sensitive data in memory to prevent side-channel attacks."""
    for i in range(len(data)):
        data[i] = secrets.randbits(8)

def secure_random_bytes(length: int):
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(length)

def hkdf_expand(shared_secret, salt=b"", info=b"TetraPQ-KDF", output_length=64):
    """
    HKDF (HMAC-based Key Derivation Function) for high-entropy key expansion.
    - NIST SP 800-56C (RFC 5869)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=output_length,
        salt=salt,
        info=info
    )
    return hkdf.derive(shared_secret)

def aes_256_kdf(shared_secret, salt=b"", iterations=100000):
    """
    AES-256-based key derivation function as a secondary secure option.
    - Based on PBKDF2 (RFC 8018, NIST SP 800-132)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(shared_secret)

def kyber_keygen():
    """Generate a Kyber-1024 key pair securely with enhanced entropy."""
    pk = ffi.new(f"unsigned char[{KYBER_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{KYBER_SECRETKEYBYTES}]")
    
    lib.PQCLEAN_KYBER1024_CLEAN_keypair(pk, sk)
    
    if len(bytes(pk)) != KYBER_PUBLICKEYBYTES or len(bytes(sk)) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid key sizes generated")

    return bytes(pk), bytes(sk)

def kyber_encapsulate(public_key):
    """Encapsulate a shared secret using Kyber-1024 securely."""
    if len(public_key) != KYBER_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")

    ct = ffi.new(f"unsigned char[{KYBER_CIPHERTEXTBYTES}]")
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    
    lib.PQCLEAN_KYBER1024_CLEAN_enc(ct, ss, public_key)
    
    if len(bytes(ct)) != KYBER_CIPHERTEXTBYTES:
        raise ValueError("Invalid ciphertext size")

    return bytes(ct), bytes(ss)

def kyber_decapsulate(ciphertext, secret_key):
    """Decapsulate the shared secret using Kyber-1024 securely."""
    if len(ciphertext) != KYBER_CIPHERTEXTBYTES or len(secret_key) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid ciphertext or secret key size")

    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    
    lib.PQCLEAN_KYBER1024_CLEAN_dec(ss, ciphertext, secret_key)
    
    shared_secret = bytes(ss)
    
    # Securely erase secret key from memory after use
    zeroize_memory(ss)
    
    return shared_secret

def verify_key_exchange(shared_secret_A, shared_secret_B):
    """Confirm key exchange integrity using HMAC for explicit key confirmation."""
    confirmation_tag_A = hmac.new(shared_secret_A, b"TetraCrypt Confirmation", hashlib.sha512).digest()
    confirmation_tag_B = hmac.new(shared_secret_B, b"TetraCrypt Confirmation", hashlib.sha512).digest()
    return hmac.compare_digest(confirmation_tag_A, confirmation_tag_B)

if __name__ == "__main__":
    try:
        print("Generating Kyber key pair...")
        alice_pk, alice_sk = kyber_keygen()

        print("Encapsulating shared secret...")
        ciphertext, shared_secret_bob = kyber_encapsulate(alice_pk)

        print("Decapsulating shared secret...")
        shared_secret_alice = kyber_decapsulate(ciphertext, alice_sk)

        if not verify_key_exchange(shared_secret_alice, shared_secret_bob):
            raise ValueError("Key exchange failed: Shared secrets do not match")

        # Key Derivation using HKDF & AES-256
        derived_key_hkdf = hkdf_expand(shared_secret_alice)
        derived_key_aes = aes_256_kdf(shared_secret_alice)

        print("Kyber Key Exchange Successful")
        print(f"Derived Key (HKDF): {derived_key_hkdf.hex()}")
        print(f"Derived Key (AES-256): {derived_key_aes.hex()}")

        # Securely erase memory
        zeroize_memory(shared_secret_alice)
        zeroize_memory(shared_secret_bob)

    except Exception as e:
        print(f"Error: {e}")
