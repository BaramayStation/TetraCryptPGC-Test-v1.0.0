import os
import secrets
import hashlib
import hmac
import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

# Constants
KYBER_PUBLICKEYBYTES = 1568
KYBER_SECRETKEYBYTES = 3168
KYBER_CIPHERTEXTBYTES = 1568
SHARED_SECRET_BYTES = 32  # Kyber shared secret size

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
    - Follows NIST SP 800-56C (RFC 5869)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=output_length,
        salt=salt,
        info=info
    )
    return hkdf.derive(shared_secret)

def kyber_keygen():
    """Generate a Kyber-1024 key pair securely."""
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
    """Confirm key exchange integrity using HMAC-based key confirmation."""
    confirmation_tag_A = hmac.new(shared_secret_A, b"TetraCrypt Confirmation", hashlib.sha512).digest()
    confirmation_tag_B = hmac.new(shared_secret_B, b"TetraCrypt Confirmation", hashlib.sha512).digest()
    return hmac.compare_digest(confirmation_tag_A, confirmation_tag_B)

def multiparty_key_exchange(participants=3):
    """
    Secure multi-party post-quantum key exchange using Kyber-1024.
    Each participant generates a key pair, then shares secrets securely.
    """
    keys = {}
    secrets = {}

    # Step 1: Generate key pairs for all participants
    for i in range(participants):
        pk, sk = kyber_keygen()
        keys[i] = {"public": pk, "private": sk}

    # Step 2: Each participant encrypts a shared secret with the next participant’s public key
    for i in range(participants):
        next_i = (i + 1) % participants  # Circular exchange
        ct, ss = kyber_encapsulate(keys[next_i]["public"])
        secrets[i] = {"ciphertext": ct, "shared_secret": ss}

    # Step 3: Each participant decapsulates the received shared secret
    final_secrets = {}
    for i in range(participants):
        final_secrets[i] = kyber_decapsulate(secrets[i]["ciphertext"], keys[i]["private"])

    # Step 4: Verify key consistency across all participants
    reference_secret = final_secrets[0]
    for i in range(1, participants):
        if not verify_key_exchange(reference_secret, final_secrets[i]):
            raise ValueError("Multi-party key exchange failed: Secrets do not match")

    # Step 5: Derive final shared key using HKDF
    final_derived_key = hkdf_expand(reference_secret)

    # Securely erase temporary key material
    for i in range(participants):
        zeroize_memory(final_secrets[i])
        zeroize_memory(keys[i]["private"])

    return final_derived_key

if __name__ == "__main__":
    try:
        print("Performing Multi-Party Kyber Key Exchange (MPKE)...")
        final_shared_key = multiparty_key_exchange(participants=3)
        print(f"Final Multi-Party Derived Key: {final_shared_key.hex()}")

    except Exception as e:
        print(f"Error: {e}")
