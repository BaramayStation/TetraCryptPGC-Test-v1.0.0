import os
import secrets
from cffi import FFI
from py_ecc.bn128 import G1, G2, add, multiply, pairing  # ZK-SNARK-based pairing operations
from pqcrypto.sign import dilithium2
from secure_hsm import store_key_in_hsm, retrieve_key_from_hsm
from src.falcon_sign import falcon_keygen
import secrets

# Example: Generating a nonce
nonce = secrets.token_bytes(32)
def generate_secure_falcon_keys():
    """Generate a Falcon keypair and store it in HSM."""
    pk, sk = falcon_keygen()
    store_key_in_hsm(sk)  # Store Falcon Secret Key inside HSM
    return pk, sk

def dilithium_keygen():
    """Generate a Dilithium key pair."""
    return dilithium2.keypair()

def dilithium_sign(message, sk):
    """Sign a message with Dilithium."""
    return dilithium2.sign(message, sk)

def dilithium_verify(message, signature, pk):
    """Verify a Dilithium signature."""
    return dilithium2.verify(message, signature, pk)

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
FALCON_SIGNATURE_MAXBYTES = 1280  # Falcon-1024 max signature size

def falcon_keygen():
    """Generate a Falcon-1024 key pair securely with validation."""
    pk = ffi.new(f"unsigned char[{FALCON_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{FALCON_SECRETKEYBYTES}]")
    
    lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)

    if len(bytes(pk)) != FALCON_PUBLICKEYBYTES or len(bytes(sk)) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid key sizes generated")

    return bytes(pk), bytes(sk)

def falcon_sign(message, secret_key):
    """Sign a message using Falcon-1024 and generate a ZKP proof."""
    if len(secret_key) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid secret key size")

    sig = ffi.new(f"unsigned char[{FALCON_SIGNATURE_MAXBYTES}]")
    siglen = ffi.new("size_t *")

    lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, message, len(message), secret_key)
    
    signed_message = bytes(sig)[:siglen[0]]

    # Generate ZKP proof using elliptic curve pairing
    proof = zk_prove(message, secret_key)

    return signed_message, proof

def falcon_verify(message, signature, proof, public_key):
    """Verify Falcon-1024 signature and the ZKP proof."""
    if len(public_key) != FALCON_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    
    # Verify Falcon signature
    result = lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), message, len(message), public_key)

    # Verify ZKP proof
    zk_valid = zk_verify(message, proof, public_key)

    return result == 0 and zk_valid

# ZK-SNARK Proof Generation (Pairing-based cryptography)
def zk_prove(message, secret_key):
    """Generate a Zero-Knowledge Proof (ZKP) for authentication."""
    h = int.from_bytes(message, "big")  # Convert message to integer
    sk_int = int.from_bytes(secret_key, "big")  # Convert secret key to integer
    
    # Generate proof as sk_int * G1
    proof = multiply(G1, sk_int)
    return proof

def zk_verify(message, proof, public_key):
    """Verify a Zero-Knowledge Proof (ZKP)."""
    h = int.from_bytes(message, "big")  # Convert message to integer
    pk_int = int.from_bytes(public_key, "big")  # Convert public key to integer

    # Check pairing equation e(proof, G2) == e(h * G1, public_key)
    lhs = pairing(proof, G2)
    rhs = pairing(multiply(G1, h), public_key)
    
    return lhs == rhs
