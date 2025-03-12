import hashlib
import secrets
from cffi import FFI

ffi = FFI()
FALCON_LIB_PATH = "./libpqclean_falcon1024_clean.so"
lib = ffi.dlopen(FALCON_LIB_PATH)

ffi.cdef("""
    void PQCLEAN_FALCON1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
    int PQCLEAN_FALCON1024_CLEAN_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
""")

FALCON_PUBLICKEYBYTES = 1792
FALCON_SECRETKEYBYTES = 2304
FALCON_SIGNATUREBYTES = 1280
MESSAGE_HASH_BYTES = 32  

def secure_erase(buffer):
    """Securely erase memory to prevent key leaks."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)

def falcon_keygen():
    """Generate a Falcon-1024 key pair securely."""
    pk = ffi.new(f"unsigned char[{FALCON_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{FALCON_SECRETKEYBYTES}]")

    lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)
    return bytes(pk), bytes(sk)

def falcon_sign(message, secret_key):
    """Sign a message using Falcon-1024 with additional entropy checks."""
    if len(secret_key) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid Falcon secret key size")

    sig = ffi.new(f"unsigned char[{FALCON_SIGNATUREBYTES}]")
    siglen = ffi.new("size_t *")

    message_hash = hashlib.sha3_512(message).digest()

    lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, message_hash, len(message_hash), secret_key)
    signed_message = bytes(sig)[:siglen[0]]

    secure_erase(sig)
    return signed_message

def falcon_verify(message, signature, public_key):
    """Verify a Falcon-1024 signature."""
    if len(public_key) != FALCON_PUBLICKEYBYTES:
        raise ValueError("Invalid Falcon public key size")

    message_hash = hashlib.sha3_512(message).digest()
    result = lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), message_hash, len(message_hash), public_key)
    return result == 0

if __name__ == "__main__":
    try:
        print("Generating Falcon key pair...")
        public_key, _ = falcon_keygen()

        message = b"Secure post-quantum authentication"
        print("Signing message...")
        signature = falcon_sign(message, _)

        print("Verifying signature...")
        is_valid = falcon_verify(message, signature, public_key)

        if not is_valid:
            raise ValueError("Signature verification failed")

        print("Falcon Signature Authentication Successful")

    except Exception as e:
        print(f"Error: {e}")
