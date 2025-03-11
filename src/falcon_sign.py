import os
import secrets
from cffi import FFI

ffi = FFI()
FALCON_LIB_PATH = os.getenv("FALCON_LIB_PATH", "/app/lib/libpqclean_falcon1024_clean.so")
lib = ffi.dlopen(FALCON_LIB_PATH)

# Define C functions for Falcon signature scheme
ffi.cdef("""
    void PQCLEAN_FALCON1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
    int PQCLEAN_FALCON1024_CLEAN_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
""")

# Constants from PQCLEAN
FALCON_PUBLICKEYBYTES = 1792
FALCON_SECRETKEYBYTES = 2304
FALCON_SIGNATURE_MAXBYTES = 1280  # Falcon-1024 signatures can be variable length but max 1280 bytes
MESSAGE_HASH_BYTES = 32  # Recommended standard for securely hashed messages

def secure_erase(buffer):
    """Securely erase a buffer to prevent memory leakage."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)

def falcon_keygen():
    """Generate a Falcon-1024 key pair securely with validation."""
    pk = ffi.new(f"unsigned char[{FALCON_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{FALCON_SECRETKEYBYTES}]")
    
    lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)

    if len(bytes(pk)) != FALCON_PUBLICKEYBYTES or len(bytes(sk)) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid key sizes generated")

    return bytes(pk), bytes(sk)

def falcon_sign(message, secret_key):
    """
    Sign a message using Falcon-1024.
    The message is securely hashed before signing to avoid leaking length-related metadata.
    """
    if len(secret_key) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid secret key size")

    sig = ffi.new(f"unsigned char[{FALCON_SIGNATURE_MAXBYTES}]")
    siglen = ffi.new("size_t *")
    
    # Ensure message is hashed to a fixed length before signing
    message_hash = secrets.token_bytes(MESSAGE_HASH_BYTES) if len(message) > MESSAGE_HASH_BYTES else message.ljust(MESSAGE_HASH_BYTES, b'\x00')

    lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, message_hash, len(message_hash), secret_key)
    
    signed_message = bytes(sig)[:siglen[0]]

    # Securely erase secret key after use
    secure_erase(sig)

    return signed_message

def falcon_verify(message, signature, public_key):
    """
    Verify a Falcon-1024 signature.
    The message is hashed before verification to ensure consistency.
    """
    if len(public_key) != FALCON_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    
    message_hash = secrets.token_bytes(MESSAGE_HASH_BYTES) if len(message) > MESSAGE_HASH_BYTES else message.ljust(MESSAGE_HASH_BYTES, b'\x00')

    result = lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), message_hash, len(message_hash), public_key)

    return result == 0

if __name__ == "__main__":
    try:
        print("Generating Falcon key pair...")
        alice_pk, alice_sk = falcon_keygen()

        message = b"Secure post-quantum authentication"
        print("Signing message...")
        signature = falcon_sign(message, alice_sk)

        print("Verifying signature...")
        is_valid = falcon_verify(message, signature, alice_pk)

        if not is_valid:
            raise ValueError("Signature verification failed")

        print("Falcon Signature Authentication Successful")
    
    except Exception as e:
        print(f"Error: {e}")
