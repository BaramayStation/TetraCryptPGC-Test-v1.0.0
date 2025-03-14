import os
import logging
from cffi import FFI
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ✅ Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ✅ Load ML-KEM Library (PQClean - FIPS 206)
ML_KEM_LIB_PATH = os.getenv("ML_KEM_LIB_PATH", "/usr/local/lib/libml-kem.so")
ffi = FFI()

try:
    ml_kem_lib = ffi.dlopen(ML_KEM_LIB_PATH)
    logging.info("[✔] ML-KEM library successfully loaded.")
except Exception as e:
    logging.error(f"[ERROR] Could not load ML-KEM library: {e}")
    raise RuntimeError("ML-KEM library missing or not installed.")

# ✅ Define ML-KEM C Bindings (PQClean FIPS 206)
ffi.cdef("""
    int PQCLEAN_MLKEM1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    int PQCLEAN_MLKEM1024_CLEAN_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int PQCLEAN_MLKEM1024_CLEAN_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
""")

ML_KEM_PUBLICKEYBYTES = 1568
ML_KEM_SECRETKEYBYTES = 3168
ML_KEM_CIPHERTEXTBYTES = 1568
SHARED_SECRET_BYTES = 32  # 256-bit shared secret

class MLKEM1024:
    """Implements FIPS 206 ML-KEM-1024 for Post-Quantum Key Encapsulation."""

    @staticmethod
    def generate_keypair():
        """
        Generate an ML-KEM-1024 key pair.
        Returns:
            tuple: (public_key, secret_key)
        """
        pk = ffi.new(f"unsigned char[{ML_KEM_PUBLICKEYBYTES}]")
        sk = ffi.new(f"unsigned char[{ML_KEM_SECRETKEYBYTES}]")

        ret = ml_kem_lib.PQCLEAN_MLKEM1024_CLEAN_keypair(pk, sk)
        if ret != 0:
            raise RuntimeError("[ERROR] ML-KEM key generation failed.")

        return bytes(pk), bytes(sk)

    @staticmethod
    def encapsulate(public_key):
        """
        Encapsulate a shared secret using ML-KEM-1024.
        Args:
            public_key (bytes): The public key of the recipient.
        Returns:
            tuple: (ciphertext, shared_secret)
        """
        if len(public_key) != ML_KEM_PUBLICKEYBYTES:
            raise ValueError("[ERROR] Invalid ML-KEM public key size.")

        ct = ffi.new(f"unsigned char[{ML_KEM_CIPHERTEXTBYTES}]")
        ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
        pk = ffi.new(f"unsigned char[{ML_KEM_PUBLICKEYBYTES}]", public_key)

        ret = ml_kem_lib.PQCLEAN_MLKEM1024_CLEAN_enc(ct, ss, pk)
        if ret != 0:
            raise RuntimeError("[ERROR] ML-KEM encapsulation failed.")

        return bytes(ct), MLKEM1024._derive_key(bytes(ss))

    @staticmethod
    def decapsulate(ciphertext, secret_key):
        """
        Decapsulate a received ciphertext using the secret key.
        Args:
            ciphertext (bytes): The ciphertext received.
            secret_key (bytes): The secret key of the recipient.
        Returns:
            bytes: The derived shared secret.
        """
        if len(ciphertext) != ML_KEM_CIPHERTEXTBYTES:
            raise ValueError("[ERROR] Invalid ML-KEM ciphertext size.")
        if len(secret_key) != ML_KEM_SECRETKEYBYTES:
            raise ValueError("[ERROR] Invalid ML-KEM secret key size.")

        ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")
        ct = ffi.new(f"unsigned char[{ML_KEM_CIPHERTEXTBYTES}]", ciphertext)
        sk = ffi.new(f"unsigned char[{ML_KEM_SECRETKEYBYTES}]", secret_key)

        ret = ml_kem_lib.PQCLEAN_MLKEM1024_CLEAN_dec(ss, ct, sk)
        if ret != 0:
            raise RuntimeError("[ERROR] ML-KEM decapsulation failed.")

        return MLKEM1024._derive_key(bytes(ss))

    @staticmethod
    def _derive_key(shared_secret):
        """
        Derives a secure shared key from the raw ML-KEM shared secret.
        Uses HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
        Args:
            shared_secret (bytes): The shared secret from ML-KEM.
        Returns:
            bytes: The final cryptographic key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=32,  # Derive a 256-bit key
            salt=None,
            info=b"TetraCryptPQC ML-KEM-1024 Key Derivation",
        )
        return hkdf.derive(shared_secret)

# ================================
# 🔹 Example Usage & Verification
# ================================
if __name__ == "__main__":
    logging.info("🔹 Testing ML-KEM-1024 Implementation...")

    kem = MLKEM1024()

    # Generate keypairs for Alice & Bob
    alice_pk, alice_sk = kem.generate_keypair()
    bob_pk, bob_sk = kem.generate_keypair()

    logging.info(f"🔑 Alice Public Key: {alice_pk.hex()}")
    logging.info(f"🔒 Alice Secret Key: {alice_sk.hex()}")

    # Alice encapsulates a key for Bob
    ciphertext, alice_shared_secret = kem.encapsulate(bob_pk)
    logging.info(f"📦 Encapsulated Ciphertext: {ciphertext.hex()}")

    # Bob decapsulates and retrieves the same shared secret
    bob_shared_secret = kem.decapsulate(ciphertext, bob_sk)

    # Ensure both parties derive the same shared secret
    assert alice_shared_secret == bob_shared_secret, "[❌] ML-KEM Key Exchange Failed!"
    logging.info("[✔] ML-KEM Key Exchange Successful!")