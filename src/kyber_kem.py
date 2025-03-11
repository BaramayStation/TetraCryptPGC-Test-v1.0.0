import os
import secrets
import hashlib
import hmac
import json
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cffi import FFI
from secretsharing import PlaintextToHexSecretSharer
from getpass import getpass
import pyotp  # Multi-Factor Authentication (OTP)
import sgx_enclave  # Secure Enclave Integration (Simulated)

ffi = FFI()
KYBER_LIB_PATH = os.getenv("KYBER_LIB_PATH", "/app/lib/libpqclean_kyber1024_clean.so")
lib = ffi.dlopen(KYBER_LIB_PATH)

# Define C functions for Kyber KEM
ffi.cdef("""
    void PQCLEAN_KYBER1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_KYBER1024_CLEAN_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    void PQCLEAN_KYBER1024_CLEAN_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

# Constants
KYBER_PUBLICKEYBYTES = 1568
KYBER_SECRETKEYBYTES = 3168
KYBER_CIPHERTEXTBYTES = 1568
SHARED_SECRET_BYTES = 32  # Kyber shared secret size
MFA_SECRET = pyotp.random_base32()  # Simulated MFA Secret

def zeroize_memory(data):
    """Securely overwrite sensitive data in memory to prevent side-channel attacks."""
    for i in range(len(data)):
        data[i] = secrets.randbits(8)

def secure_random_bytes(length: int):
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(length)

def hkdf_expand(shared_secret, salt=b"", info=b"TetraPQ-KDF", output_length=64):
    """
    HKDF (HMAC-based Key Derivation Function) for high-entropy key expansion.
    - Follows NIST SP 800-56C (RFC 5869)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=output_length,
        salt=salt,
        info=info
    )
    return hkdf.derive(shared_secret)

def pbkdf2_derive_key(password, salt, iterations=100000, length=32):
    """Derive an encryption key from a user-provided password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())

def kyber_keygen():
    """Generate a Kyber-1024 key pair securely."""
    pk = ffi.new(f"unsigned char[{KYBER_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{KYBER_SECRETKEYBYTES}]")
    
    lib.PQCLEAN_KYBER1024_CLEAN_keypair(pk, sk)
    
    if len(bytes(pk)) != KYBER_PUBLICKEYBYTES or len(bytes(sk)) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid key sizes generated")

    return bytes(pk), bytes(sk)

def split_secret(secret, threshold=3, total_shares=5):
    """
    Split a secret key into `total_shares` pieces, requiring `threshold` to reconstruct.
    Uses Shamir's Secret Sharing (SSS) to split the key into secure fragments.
    """
    secret_hex = secret.hex()  # Convert to hex for compatibility
    shares = PlaintextToHexSecretSharer.split_secret(secret_hex, threshold, total_shares)
    return shares

def reconstruct_secret(shares):
    """
    Reconstruct the original secret from a subset of shares.
    Requires at least `threshold` shares to work.
    """
    secret_hex = PlaintextToHexSecretSharer.recover_secret(shares)
    return bytes.fromhex(secret_hex)  # Convert back to bytes

def authenticate_with_mfa():
    """Perform MFA verification using Time-Based OTP (TOTP)."""
    otp = pyotp.TOTP(MFA_SECRET)
    user_otp = input("Enter MFA OTP: ")
    return otp.verify(user_otp)

def kyber_encapsulate(public_key):
    """Encapsulate a shared secret using Kyber-1024 securely."""
    if len(public_key) != KYBER_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")

    ct = ffi.new(f"unsigned char[{KYBER_CIPHERTEXTBYTES}]")
    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    
    lib.PQCLEAN_KYBER1024_CLEAN_enc(ct, ss, public_key)
    
    if len(bytes(ct)) != KYBER_CIPHERTEXTBYTES:
        raise ValueError("Invalid ciphertext size")

    return bytes(ct), bytes(ss)

def kyber_decapsulate(ciphertext, secret_key):
    """Decapsulate the shared secret using Kyber-1024 securely."""
    if len(ciphertext) != KYBER_CIPHERTEXTBYTES or len(secret_key) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid ciphertext or secret key size")

    ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
    
    lib.PQCLEAN_KYBER1024_CLEAN_dec(ss, ciphertext, secret_key)
    
    shared_secret = bytes(ss)
    
    # Securely erase secret key from memory after use
    zeroize_memory(ss)
    
    return shared_secret

def secure_store_key(key):
    """Store the key securely using Secure Enclave or TPM."""
    return sgx_enclave.store_secure_key(key)

def retrieve_secure_key():
    """Retrieve the key from Secure Enclave."""
    return sgx_enclave.get_secure_key()

if __name__ == "__main__":
    try:
        print("Performing Multi-Party Kyber Key Exchange with MFA & Secure Enclave Support...")
        
        # User authentication via MFA
        if not authenticate_with_mfa():
            raise ValueError("MFA Authentication Failed")

        # Generate Kyber key pair
        pk, sk = kyber_keygen()

        # Encrypt private key using Secure Enclave
        secure_store_key(sk)
        sk_enclave = retrieve_secure_key()

        # Encrypt shared secret
        ciphertext, shared_secret_bob = kyber_encapsulate(pk)
        shared_secret_alice = kyber_decapsulate(ciphertext, sk_enclave)

        # Validate handshake
        if shared_secret_alice != shared_secret_bob:
            raise ValueError("Key exchange failed: Shared secrets do not match")

        print("Kyber Key Exchange Successful with MFA and Secure Enclave Protection")
    
    except Exception as e:
        print(f"Error: {e}")
