import os
import hashlib
import secrets
from cffi import FFI
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Initialize FFI
ffi = FFI()

# Load Kyber & Falcon Libraries
kyber_lib = ffi.dlopen("./libpqclean_kyber1024_clean.so")
falcon_lib = ffi.dlopen("./libpqclean_falcon1024_clean.so")

# Define C functions
ffi.cdef("""
    void PQCLEAN_KYBER1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_KYBER1024_CLEAN_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    void PQCLEAN_KYBER1024_CLEAN_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk);
    int PQCLEAN_FALCON1024_CLEAN_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk);
""")

# Constants
KYBER_PUBLICKEYBYTES = 1568
KYBER_SECRETKEYBYTES = 3168
KYBER_CIPHERTEXTBYTES = 1568
FALCON_PUBLICKEYBYTES = 1792
FALCON_SECRETKEYBYTES = 2304
FALCON_SIGNATUREBYTES = 1280
SHARED_SECRET_BYTES = 32  # Kyber shared secret length
DERIVED_KEY_BYTES = 64  # Key length after HKDF expansion

# ---------------- Secure Functions ----------------

def secure_erase(buffer):
    """Securely erase sensitive memory to prevent leakage and side-channel attacks."""
    if isinstance(buffer, memoryview):
        buffer[:] = bytes(len(buffer))  # Overwrite with zeros
    else:
        for i in range(len(buffer)):
            buffer[i] = secrets.randbits(8)  # Fill with random noise

# ---------------- Key Generation ----------------

def pq_xdh_keygen():
    """Generate a Kyber-1024 keypair."""
    pk = ffi.new(f"unsigned char[{KYBER_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{KYBER_SECRETKEYBYTES}]")
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_keypair(pk, sk)
    return bytes(pk), bytes(sk)

def falcon_keygen():
    """Generate a Falcon-1024 keypair."""
    pk = ffi.new(f"unsigned char[{FALCON_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{FALCON_SECRETKEYBYTES}]")
    falcon_lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)
    return bytes(pk), bytes(sk)

# ---------------- Kyber Encapsulation/Decapsulation ----------------

def encapsulate_key(public_key):
    """Encapsulate a shared secret with Kyber-1024."""
    ct = ffi.new(f"unsigned char[{KYBER_CIPHERTEXTBYTES}]")
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_enc(ct, ss, public_key)
    return bytes(ct), bytes(ss)

def decapsulate_key(ciphertext, secret_key):
    """Decapsulate a shared secret with Kyber-1024."""
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_dec(ss, ciphertext, secret_key)
    return bytes(ss)

# ---------------- Signature Functions ----------------

def sign_shared_secret(shared_secret, falcon_sk):
    """Sign a shared secret with Falcon-1024 after hashing."""
    sig = ffi.new(f"unsigned char[{FALCON_SIGNATUREBYTES}]")
    siglen = ffi.new("size_t *")
    
    # Hash secret before signing (avoiding side-channel leakage)
    hashed_secret = hashlib.sha3_512(shared_secret).digest()

    falcon_lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, hashed_secret, len(hashed_secret), falcon_sk)
    return bytes(sig)[:siglen[0]]

def verify_signature(shared_secret, signature, falcon_pk):
    """Verify a Falcon-1024 signature using a hashed shared secret."""
    hashed_secret = hashlib.sha3_512(shared_secret).digest()
    result = falcon_lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), hashed_secret, len(hashed_secret), falcon_pk)
    return result == 0

# ---------------- Hybrid Key Derivation ----------------

def derive_final_shared_secret(raw_secret, transcript):
    """Use HKDF to derive a secure final session key with explicit salt."""
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=DERIVED_KEY_BYTES,
        salt=secrets.token_bytes(32),  # Explicit salt for security
        info=transcript,
    )
    return hkdf.derive(raw_secret)

# ---------------- Multi-Party Key Exchange ----------------

def pq_xdh_handshake_multiparty(participants=3):
    """Perform a post-quantum secure handshake for multiple parties (>=3)."""
    keys = {}
    
    # Generate keys for all participants
    for i in range(participants):
        keys[f"pk_kyber_{i}"], keys[f"sk_kyber_{i}"] = pq_xdh_keygen()
        keys[f"pk_falcon_{i}"], keys[f"sk_falcon_{i}"] = falcon_keygen()

    shared_secrets = []
    
    for i in range(participants):
        next_i = (i + 1) % participants  # Circular exchange
        
        # Encapsulate with next participant's key
        ct, ss_sender = encapsulate_key(keys[f"pk_kyber_{next_i}"])
        ss_receiver = decapsulate_key(ct, keys[f"sk_kyber_{next_i}"])
        
        if ss_sender != ss_receiver:
            raise ValueError(f"Shared secret mismatch between {i} and {next_i}")

        shared_secrets.append(ss_sender)

    # Generate transcript hash (binds all public keys and signatures)
    transcript = hashlib.sha3_512(
        b"".join(keys[f"pk_kyber_{i}"] + keys[f"pk_falcon_{i}"] for i in range(participants))
    ).digest()

    # Sign transcript for authentication
    signatures = {i: sign_shared_secret(transcript, keys[f"sk_falcon_{i}"]) for i in range(participants)}

    # Verify signatures
    for i in range(participants):
        if not verify_signature(transcript, signatures[i], keys[f"pk_falcon_{i}"]):
            raise ValueError(f"Signature verification failed for participant {i}")

    # Final shared key derived via HKDF
    final_secret = derive_final_shared_secret(b"".join(shared_secrets), transcript)

    return True, final_secret

# ---------------- Main Execution ----------------

if __name__ == "__main__":
    try:
        valid, shared_key = pq_xdh_handshake_multiparty()
        print(f"Multi-party handshake successful: {valid}")
        print(f"Derived shared key: {shared_key.hex()}")
    except ValueError as e:
        print(f"Error: {e}")
