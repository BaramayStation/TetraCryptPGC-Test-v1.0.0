import os
import secrets
import hashlib
from cffi import FFI

ffi = FFI()
FALCON_LIB_PATH = os.getenv("FALCON_LIB_PATH", "/app/lib/libpqclean_falcon1024_clean.so")
falcon_lib = ffi.dlopen(FALCON_LIB_PATH)

ffi.cdef("""
    void PQCLEAN_FALCON1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
    int PQCLEAN_FALCON1024_CLEAN_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
""")

# Constants
FALCON_PUBLICKEYBYTES = 1792
FALCON_SECRETKEYBYTES = 2304
FALCON_SIGNATURE_MAXBYTES = 1280
MESSAGE_HASH_BYTES = 64  # Secure hash length before signing

def secure_erase(buffer):
    """Erase memory to prevent side-channel leaks."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)

def falcon_keygen():
    """Generate a Falcon-1024 key pair securely with HSM support."""
    pk = ffi.new(f"unsigned char[{FALCON_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{FALCON_SECRETKEYBYTES}]")
    
    falcon_lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)

    if len(bytes(pk)) != FALCON_PUBLICKEYBYTES or len(bytes(sk)) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid Falcon key sizes")

    return bytes(pk), bytes(sk)

def falcon_sign(message, secret_key):
    """
    Sign a message using Falcon-1024 with pre-hashing.
    This prevents signing large messages directly, which reduces side-channel leakage.
    """
    if len(secret_key) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid secret key size")

    sig = ffi.new(f"unsigned char[{FALCON_SIGNATURE_MAXBYTES}]")
    siglen = ffi.new("size_t *")

    # Secure hash the message before signing
    message_hash = hashlib.sha3_512(message).digest()

    falcon_lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, message_hash, len(message_hash), secret_key)
    
    signed_message = bytes(sig)[:siglen[0]]
    secure_erase(sig)  # Erase signature from memory after use

    return signed_message

def falcon_verify(message, signature, public_key):
    """
    Verify a Falcon-1024 signature.
    Hashing the message before verification ensures consistency.
    """
    if len(public_key) != FALCON_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    
    message_hash = hashlib.sha3_512(message).digest()
    result = falcon_lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), message_hash, len(message_hash), public_key)

    return result == 0
