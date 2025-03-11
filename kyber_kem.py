import os
from cffi import FFI

ffi = FFI()
lib = ffi.dlopen("/app/lib/libpqclean_kyber1024_clean.so")  # Match Dockerfile path

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

def kyber_keygen():
    """Generate a Kyber-1024 key pair."""
    pk = ffi.new("unsigned char[{}]".format(KYBER_PUBLICKEYBYTES))
    sk = ffi.new("unsigned char[{}]".format(KYBER_SECRETKEYBYTES))
    lib.PQCLEAN_KYBER1024_CLEAN_keypair(pk, sk)
    if len(bytes(pk)) != KYBER_PUBLICKEYBYTES or len(bytes(sk)) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid key sizes generated")
    return bytes(pk), bytes(sk)

def kyber_encapsulate(public_key):
    """Encapsulate a shared secret using Kyber-1024."""
    if len(public_key) != KYBER_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    ct = ffi.new("unsigned char[{}]".format(KYBER_CIPHERTEXTBYTES))
    ss = ffi.new("unsigned char[32]")  # Shared secret is 32 bytes
    lib.PQCLEAN_KYBER1024_CLEAN_enc(ct, ss, public_key)
    if len(bytes(ct)) != KYBER_CIPHERTEXTBYTES:
        raise ValueError("Invalid ciphertext size")
    return bytes(ct), bytes(ss)

def kyber_decapsulate(ciphertext, secret_key):
    """Decapsulate the shared secret using Kyber-1024."""
    if len(ciphertext) != KYBER_CIPHERTEXTBYTES or len(secret_key) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid ciphertext or secret key size")
    ss = ffi.new("unsigned char[32]")
    lib.PQCLEAN_KYBER1024_CLEAN_dec(ss, ciphertext, secret_key)
    return bytes(ss)

if __name__ == "__main__":
    try:
        # Example usage
        alice_pk, alice_sk = kyber_keygen()
        ciphertext, shared_secret_bob = kyber_encapsulate(alice_pk)
        shared_secret_alice = kyber_decapsulate(ciphertext, alice_sk)

        if shared_secret_alice != shared_secret_bob:
            raise ValueError("Key exchange failed: Shared secrets do not match")
        print("Kyber Key Exchange Successful")
    except Exception as e:
        print(f"Error: {e}")
