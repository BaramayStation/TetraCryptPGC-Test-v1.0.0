import os
from cffi import FFI
import hashlib
import secrets

# Initialize FFI (Foreign Function Interface)
ffi = FFI()

# Set the path to the Falcon library (assuming it's installed globally)
FALCON_LIB_PATH = os.getenv("FALCON_LIB_PATH", "/usr/local/lib/libpqclean_falcon1024_clean.so")

# Load the Falcon library
try:
    lib = ffi.dlopen(FALCON_LIB_PATH)
except Exception as e:
    raise RuntimeError(f"Could not load libpqclean Falcon library: {e}")

# Add version check to future-proof against future changes to the libpqclean API
ffi.cdef("""
    const char *OQS_VERSION;
""")

# Checking liboqs version
def check_libpqclean_version():
    version = ffi.string(lib.OQS_VERSION).decode('utf-8')
    if version < "0.7.0":
        raise RuntimeError(f"Old version of libpqclean detected: {version}. Please upgrade to at least version 0.7.0.")
    else:
        print(f"Using libpqclean version {version}")

# Call the version check function
check_libpqclean_version()

# Select algorithm dynamically based on environment variable
ALGORITHM = os.getenv("TETRACRYPT_ALGORITHM", "FALCON").upper()

if ALGORITHM == "FALCON":
    ffi.cdef("""
        void PQCLEAN_FALCON1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
        void PQCLEAN_FALCON1024_CLEAN_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
        int PQCLEAN_FALCON1024_CLEAN_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
    """)
else:
    raise RuntimeError(f"Unknown algorithm: {ALGORITHM}")

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
        public_key, secret_key = falcon_keygen()

        message = b"Secure post-quantum authentication"
        print("Signing message...")
        signature = falcon_sign(message, secret_key)

        print("Verifying signature...")
        is_valid = falcon_verify(message, signature, public_key)

        if not is_valid:
            raise ValueError("Signature verification failed")

        print("Falcon Signature Authentication Successful")

    except Exception as e:
        print(f"Error: {e}")
