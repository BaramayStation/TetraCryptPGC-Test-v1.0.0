import os
from cffi import FFI

# Initialize FFI (Foreign Function Interface)
ffi = FFI()

# Set the path to the liboqs library (assuming it's installed globally)
KYBER_LIB_PATH = os.getenv("KYBER_LIB_PATH", "/usr/local/lib/liboqs.so")

# Load the Kyber library
try:
    kyber_lib = ffi.dlopen(KYBER_LIB_PATH)
except Exception as e:
    raise RuntimeError(f"Could not load liboqs library: {e}")

# Define the Kyber KEM functions (using liboqs)
ffi.cdef("""
    int OQS_KEM_KYBER1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_KEM_KYBER1024_encapsulate(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int OQS_KEM_KYBER1024_decapsulate(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

# Kyber key generation function
def kyber_keygen():
    pk = ffi.new("unsigned char[1568]")  # Public key size for Kyber-1024
    sk = ffi.new("unsigned char[3168]")  # Secret key size for Kyber-1024

    # Generate Kyber-1024 keypair
    ret = kyber_lib.OQS_KEM_KYBER1024_keypair(pk, sk)
    if ret != 0:
        raise ValueError("Key generation failed.")

    return bytes(pk), bytes(sk)

# Kyber-1024 encapsulation function
def kyber_encapsulate(public_key):
    ct = ffi.new("unsigned char[1568]")  # Ciphertext size
    ss = ffi.new("unsigned char[32]")  # Shared secret size

    # Encapsulate the shared secret
    ret = kyber_lib.OQS_KEM_KYBER1024_encapsulate(ct, ss, public_key)
    if ret != 0:
        raise ValueError("Encapsulation failed.")

    return bytes(ct), bytes(ss)

# Kyber-1024 decapsulation function
def kyber_decapsulate(ciphertext, secret_key):
    ss = ffi.new("unsigned char[32]")  # Shared secret size

    # Decapsulate the shared secret
    ret = kyber_lib.OQS_KEM_KYBER1024_decapsulate(ss, ciphertext, secret_key)
    if ret != 0:
        raise ValueError("Decapsulation failed.")

    return bytes(ss)
