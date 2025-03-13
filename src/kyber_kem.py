import os
from cffi import FFI
import secrets

# Initialize FFI (Foreign Function Interface)
ffi = FFI()

# Set the path to the liboqs library (assuming it's installed globally)
KYBER_LIB_PATH = os.getenv("KYBER_LIB_PATH", "/usr/local/lib/liboqs.so")

# Load the Kyber library
try:
    kyber_lib = ffi.dlopen(KYBER_LIB_PATH)
except Exception as e:
    raise RuntimeError(f"Could not load liboqs library: {e}")

# Add version check to future-proof against future changes to the liboqs API
ffi.cdef("""
    const char *OQS_VERSION;
""")

# Checking liboqs version
def check_liboqs_version():
    version = ffi.string(kyber_lib.OQS_VERSION).decode('utf-8')
    if version < "0.7.0":
        raise RuntimeError(f"Old version of liboqs detected: {version}. Please upgrade to at least version 0.7.0.")
    else:
        print(f"Using liboqs version {version}")

# Call the version check function
check_liboqs_version()

# Define the Kyber KEM functions (using liboqs)
ffi.cdef("""
    int OQS_KEM_KYBER1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_KEM_KYBER1024_encapsulate(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int OQS_KEM_KYBER1024_decapsulate(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

# Select algorithm dynamically based on environment variable
ALGORITHM = os.getenv("TETRACRYPT_ALGORITHM", "KYBER").upper()

if ALGORITHM == "KYBER":
    ffi.cdef("""
        int OQS_KEM_KYBER1024_keypair(unsigned char *pk, unsigned char *sk);
        int OQS_KEM_KYBER1024_encapsulate(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
        int OQS_KEM_KYBER1024_decapsulate(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    """)
elif ALGORITHM == "FALCON":
    ffi.cdef("""
        // Define Falcon's functions here (e.g., signature generation)
    """)
else:
    raise RuntimeError(f"Unknown algorithm: {ALGORITHM}")

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

# Securely erase sensitive memory to prevent leaks
def secure_erase(buffer):
    """Securely erase sensitive memory to prevent leaks."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)

# Example usage of kyber_keygen and secure_erase
pk, sk = kyber_keygen()
secure_erase(sk)  # Securely erase the secret key after use
