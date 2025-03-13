import os
import logging
from cffi import FFI

# ✅ Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ✅ Load ML-KEM Library (FIPS 206)
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
SHARED_SECRET_BYTES = 32

class ML_KEM:
    """Implements FIPS 206 ML-KEM-1024 for Post-Quantum Key Encapsulation."""

    @staticmethod
    def generate_keypair():
        """Generate an ML-KEM-1024 key pair."""
        pk = ffi.new(f"unsigned char[{ML_KEM_PUBLICKEYBYTES}]")
        sk = ffi.new(f"unsigned char[{ML_KEM_SECRETKEYBYTES}]")

        ret = ml_kem_lib.PQCLEAN_MLKEM1024_CLEAN_keypair(pk, sk)
        if ret != 0:
            raise RuntimeError("ML-KEM key generation failed.")

        return bytes(pk), bytes(sk)

    @staticmethod
    def encapsulate(public_key):
        """Encapsulate a shared secret using ML-KEM-1024."""
        ct = ffi.new(f"unsigned char[{ML_KEM_CIPHERTEXTBYTES}]")
        ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")

        ret = ml_kem_lib.PQCLEAN_MLKEM1024_CLEAN_enc(ct, ss, public_key)
        if ret != 0:
            raise RuntimeError("ML-KEM encapsulation failed.")

        return bytes(ct), bytes(ss)

    @staticmethod
    def decapsulate(ciphertext, secret_key):
        """Decapsulate the shared secret using ML-KEM-1024."""
        ss = ffi.new(f"unsigned char[{SHARED_SECRET_BYTES}]")

        ret = ml_kem_lib.PQCLEAN_MLKEM1024_CLEAN_dec(ss, ciphertext, secret_key)
        if ret != 0:
            raise RuntimeError("ML-KEM decapsulation failed.")

        return bytes(ss)

# ✅ Example Usage
if __name__ == "__main__":
    logging.info("🔹 Testing ML-KEM-1024 Implementation...")

    pk, sk = ML_KEM.generate_keypair()
    logging.info(f"🔑 Public Key: {pk.hex()}")
    logging.info(f"🔒 Secret Key: {sk.hex()}")

    ciphertext, shared_secret_enc = ML_KEM.encapsulate(pk)
    logging.info(f"📦 Encapsulated Ciphertext: {ciphertext.hex()}")

    shared_secret_dec = ML_KEM.decapsulate(ciphertext, sk)
    
    if shared_secret_enc == shared_secret_dec:
        logging.info("[✔] ML-KEM Key Exchange Successful!")
    else:
        logging.error("[❌] ML-KEM Key Exchange Failed!")
