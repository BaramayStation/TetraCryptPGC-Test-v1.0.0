from cffi import FFI

ffi = FFI()
lib = ffi.dlopen("/app/lib/libpqclean_falcon1024_clean.so")  # Match Dockerfile path

# Define C functions for Falcon signing and verification
ffi.cdef("""
    void PQCLEAN_FALCON1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk);
    int PQCLEAN_FALCON1024_CLEAN_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk);
""")

# Correct constants for Falcon-1024 (from PQCLEAN)
FALCON_PUBLICKEYBYTES = 1281
FALCON_SECRETKEYBYTES = 2305
FALCON_SIGNATUREBYTES = 1280

def falcon_keygen():
    """Generate Falcon-1024 key pair."""
    pk = ffi.new("unsigned char[{}]".format(FALCON_PUBLICKEYBYTES))
    sk = ffi.new("unsigned char[{}]".format(FALCON_SECRETKEYBYTES))
    lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)
    if len(bytes(pk)) != FALCON_PUBLICKEYBYTES or len(bytes(sk)) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid key sizes generated")
    return bytes(pk), bytes(sk)

def falcon_sign(message: bytes, secret_key: bytes) -> bytes:
    """Sign a message with Falcon-1024 secret key."""
    if len(secret_key) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid secret key size")
    sig = ffi.new("unsigned char[{}]".format(FALCON_SIGNATUREBYTES))
    siglen = ffi.new("size_t *")
    lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, message, len(message), secret_key)
    if siglen[0] > FALCON_SIGNATUREBYTES:
        raise ValueError("Signature exceeds maximum size")
    return bytes(sig)[:siglen[0]]

def falcon_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a Falcon-1024 signature."""
    if len(public_key) != FALCON_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    result = lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), message, len(message), public_key)
    return result == 0

if __name__ == "__main__":
    try:
        # Generate keys
        pk, sk = falcon_keygen()
        print("Public Key:", pk.hex())
        print("Secret Key:", sk.hex())
        
        # Test signing and verification
        message = b"Post-Quantum Cryptography Test"
        signature = falcon_sign(message, sk)
        print("Signature:", signature.hex())
        
        is_valid = falcon_verify(message, signature, pk)
        print("Signature valid:", is_valid)
    except Exception as e:
        print(f"Error: {e}")
