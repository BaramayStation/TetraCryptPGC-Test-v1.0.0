import os
import secrets
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

def secure_erase(buffer):
    """Securely erase a buffer to prevent memory leakage."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)

def kyber_keygen():
    """Generate a Kyber-1024 key pair securely with validation."""
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
    secure_erase(ss)
    
    return shared_secret

if __name__ == "__main__":
    try:
        print("Generating Kyber key pair...")
        alice_pk, alice_sk = kyber_keygen()

        print("Encapsulating shared secret...")
        ciphertext, shared_secret_bob = kyber_encapsulate(alice_pk)

        print("Decapsulating shared secret...")
        shared_secret_alice = kyber_decapsulate(ciphertext, alice_sk)

        if shared_secret_alice != shared_secret_bob:
            raise ValueError("Key exchange failed: Shared secrets do not match")

        print("Kyber Key Exchange Successful")
    
    except Exception as e:
        print(f"Error: {e}")
