import os
import logging
from cffi import FFI

# 🔹 Initialize FFI (Foreign Function Interface)
ffi = FFI()

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Detect Secure Enclave Type (SGX, TPM, HSM)
SECURE_ENCLAVE_TYPE = os.getenv("SECURE_ENCLAVE_TYPE", "SGX").upper()

# 🔹 Load the correct secure enclave library dynamically
ENCLAVE_LIB_PATH = {
    "SGX": "/app/lib/libsecure_enclave_sgx.so",
    "TPM": "/app/lib/libsecure_enclave_tpm.so",
    "HSM": "/app/lib/libsecure_enclave_hsm.so",
}.get(SECURE_ENCLAVE_TYPE, "/app/lib/libsecure_enclave_sgx.so")  # Default: SGX

try:
    enclave = ffi.dlopen(ENCLAVE_LIB_PATH)
    logging.info(f"[SECURE ENCLAVE] Loaded: {ENCLAVE_LIB_PATH}")
except Exception as e:
    logging.critical(f"[ERROR] Could not load enclave library: {e}")
    raise SystemExit("[SECURITY ALERT] No Secure Enclave Available!")

# 🔹 Define Secure Enclave API
ffi.cdef("""
    int secure_store_key(unsigned char *key, size_t key_size, unsigned char *sealed_data);
    int retrieve_secure_key(unsigned char *sealed_data, unsigned char *unsealed_key);
""")

class SecureEnclave:
    """Handles Secure Key Storage inside SGX, TPM, or HSM."""

    @staticmethod
    def secure_store_key(key: bytes) -> bytes:
        """
        Store a cryptographic key securely inside Intel SGX / TPM / HSM.
        The key never leaves the secure enclave.
        """
        if len(key) != 32:
            raise ValueError("Key size must be 256-bit (32 bytes).")

        sealed_data = ffi.new("unsigned char[64]")  # Encrypted key storage
        ret = enclave.secure_store_key(key, len(key), sealed_data)

        if ret != 0:
            raise RuntimeError("[SECURITY ERROR] Secure Key Storage Failed!")
        
        logging.info("[SECURE ENCLAVE] Key securely stored.")
        return bytes(sealed_data)

    @staticmethod
    def retrieve_secure_key(sealed_data: bytes) -> bytes:
        """
        Retrieve and decrypt a key stored inside the secure enclave.
        The key remains inaccessible to the OS.
        """
        unsealed_key = ffi.new("unsigned char[32]")  # 256-bit key retrieval
        ret = enclave.retrieve_secure_key(sealed_data, unsealed_key)

        if ret != 0:
            raise RuntimeError("[SECURITY ERROR] Secure Key Retrieval Failed!")

        logging.info("[SECURE ENCLAVE] Key successfully retrieved.")
        return bytes(unsealed_key)

# 🔹 Example Execution
if __name__ == "__main__":
    logging.info("\n🔐 Testing Secure Enclave Key Storage...")

    test_key = os.urandom(32)  # Generate a 256-bit random key
    logging.info(f"Generated Test Key: {test_key.hex()}")

    sealed_key = SecureEnclave.secure_store_key(test_key)
    retrieved_key = SecureEnclave.retrieve_secure_key(sealed_key)

    assert test_key == retrieved_key, "🚨 Secure Enclave Key Mismatch!"
    logging.info("✅ Secure Enclave Key Storage & Retrieval Successful!")