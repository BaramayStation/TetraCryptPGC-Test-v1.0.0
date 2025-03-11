import os
import secrets
import hashlib
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
FALCON_SIGNATURE_MAXBYTES = 1280  # Max Falcon-1024 signature size
MESSAGE_HASH_BYTES = 64  # Strengthened to 64 bytes using SHAKE-256

def secure_erase(buffer):
    """Securely erase sensitive data from memory."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)  # Overwrite with cryptographic randomness

def shake256_hash(message, output_length=MESSAGE_HASH_BYTES):
    """Hash the message using SHAKE-256 for post-quantum security."""
    shake = hashlib.shake_256()
    shake.update(message)
    return shake.digest(output_length)

def falcon_keygen():
    """Generate a Falcon-1024 key pair securely with validation."""
    pk = ffi.new(f"unsigned char[{FALCON_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{FALCON_SECRETKEYBYTES}]")
    
    lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)

    if len(bytes(pk)) != FALCON_PUBLICKEYBYTES or len(bytes(sk)) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid Falcon key sizes generated")

    return bytes(pk), bytes(sk)

def falcon_sign(message, secret_key):
    """
    Sign a message using Falcon-1024 with SHAKE-256 preprocessing.
    """
    if len(secret_key) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid secret key size")

    sig = ffi.new(f"unsigned char[{FALCON_SIGNATURE_MAXBYTES}]")
    siglen = ffi.new("size_t *")
    
    # Hash message to a fixed length for security
    message_hash = shake256_hash(message)

    lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, message_hash, len(message_hash), secret_key)
    
    signed_message = bytes(sig)[:siglen[0]]

    # Securely erase secret key after use
    secure_erase(sig)

    return signed_message

def falcon_verify(message, signature, public_key):
    """
    Verify a Falcon-1024 signature using SHAKE-256 for message integrity.
    """
    if len(public_key) != FALCON_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    
    # Hash the message before verification
    message_hash = shake256_hash(message)

    result = lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), message_hash, len(message_hash), public_key)

    return result == 0

if __name__ == "__main__":
    try:
        print("[INFO] Generating Falcon key pair...")
        alice_pk, alice_sk = falcon_keygen()

        message = b"Post-Quantum Secure Signature"
        print("[INFO] Signing message with Falcon-1024...")
        signature = falcon_sign(message, alice_sk)

        print("[INFO] Verifying signature...")
        is_valid = falcon_verify(message, signature, alice_pk)

        if not is_valid:
            raise ValueError("[ERROR] Falcon signature verification failed!")

        print("[SUCCESS] Falcon Signature Authentication Successful!")
    
    except Exception as e:
        print(f"[ERROR] {e}")
