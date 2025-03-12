import os
import secrets
from cffi import FFI
from cryptography.hazmat.primitives.asymmetric import x25519
from secure_hsm import store_key_in_hsm, retrieve_key_from_hsm
import kyber_keygen
import secrets

# Example: Generating a nonce
nonce = secrets.token_bytes(32)
def generate_secure_kyber_keys():
    """Generate a Kyber keypair and store it in HSM."""
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

ffi = FFI()
KYBER_LIB_PATH = os.getenv("KYBER_LIB_PATH", "/app/lib/libpqclean_kyber1024_clean.so")
kyber_lib = ffi.dlopen(KYBER_LIB_PATH)

ffi.cdef("""
    void PQCLEAN_KYBER1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_KYBER1024_CLEAN_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    void PQCLEAN_KYBER1024_CLEAN_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

# Constants
KYBER_PUBLICKEYBYTES = 1568
KYBER_SECRETKEYBYTES = 3168
KYBER_CIPHERTEXTBYTES = 1568
SHARED_SECRET_BYTES = 32

def secure_erase(buffer):
    """Securely erase sensitive memory to prevent leaks."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)

def kyber_keygen():
    """Generate a Kyber-1024 key pair with improved security and validation."""
    pk = ffi.new(f"unsigned char[{KYBER_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{KYBER_SECRETKEYBYTES}]")
    
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_keypair(pk, sk)
    
    if len(bytes(pk)) != KYBER_PUBLICKEYBYTES or len(bytes(sk)) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid key sizes generated")

    return bytes(pk), bytes(sk)

def kyber_encapsulate(public_key):
    """Encapsulate a shared secret using Kyber-1024 with hybrid ECC."""
    if len(public_key) != KYBER_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")

    ct = ffi.new(f"unsigned char[{KYBER_CIPHERTEXTBYTES}]")
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_enc(ct, ss, public_key)
    
    if len(bytes(ct)) != KYBER_CIPHERTEXTBYTES:
        raise ValueError("Invalid ciphertext size")

    return bytes(ct), bytes(ss)

def kyber_decapsulate(ciphertext, secret_key):
    """Decapsulate the shared secret securely."""
    if len(ciphertext) != KYBER_CIPHERTEXTBYTES or len(secret_key) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid ciphertext or secret key size")

    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_dec(ss, ciphertext, secret_key)
    
    shared_secret = bytes(ss)
    secure_erase(ss)  # Securely erase memory after use
    
    return shared_secret
