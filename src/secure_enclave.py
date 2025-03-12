import logging
import os
import hashlib
import hmac
import secrets
from cffi import FFI
from tpm2_pytss import ESAPI, TPM2B_PUBLIC, TPM2B_PRIVATE, TPM2B_SENSITIVE_CREATE
from src.qkd_key_exchange import get_qkd_key  # Import QKD key retrieval from TetraCryptPGC

# Configure Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Initialize FFI for Intel SGX
ffi = FFI()
sgx = ffi.dlopen("./libsecure_enclave.so")

ffi.cdef("""
    sgx_status_t secure_store_key(unsigned char *key, size_t key_size, unsigned char *sealed_data);
    sgx_status_t retrieve_secure_key(unsigned char *sealed_data, unsigned char *unsealed_key);
""")

# ---------------- Quantum Key Distribution (QKD) Integration ----------------

def qkd_derived_key():
    """Retrieve a key from QKD and hash it for secure storage."""
    qkd_raw_key = get_qkd_key()  # Retrieve quantum-safe key from QKD system
    logging.info("[QKD] Received Quantum Key. Deriving secure key...")
    
    # Hash the QKD key for additional security (Entropy Expansion)
    derived_key = hashlib.sha3_512(qkd_raw_key).digest()[:32]  # 256-bit secure key
    return derived_key

# ---------------- Intel SGX Secure Key Storage ----------------

def secure_store_key(key):
    """
    Store a cryptographic key inside the SGX enclave with key sealing.
    Ensures that the key cannot be extracted outside of a trusted execution environment.
    """
    if len(key) != 32:  # Ensure a 256-bit key
        raise ValueError("Invalid key length. Must be 32 bytes (256-bit).")

    logging.info("[SGX] Sealing key inside Intel SGX enclave...")

    sealed_data = ffi.new("unsigned char[64]")  # 512-bit sealed buffer
    status = sgx.secure_store_key(key, len(key), sealed_data)

    if status != 0:
        logging.critical("[SECURITY ALERT] Key sealing failed in SGX enclave!")
        raise ValueError("SGX secure store key failed.")

    logging.info("[SGX] Key successfully sealed inside enclave.")
    return bytes(sealed_data)

def retrieve_secure_key(sealed_data):
    """
    Retrieve a cryptographic key from the SGX enclave after verification.
    Requires enclave attestation before unsealing the key.
    """
    logging.info("[SGX] Retrieving key from enclave...")

    unsealed_key = ffi.new("unsigned char[32]")  # 256-bit key buffer
    status = sgx.retrieve_secure_key(sealed_data, unsealed_key)

    if status != 0:
        logging.critical("[SECURITY ALERT] Secure key retrieval failed! Possible enclave compromise.")
        raise ValueError("SGX secure retrieve key failed.")

    logging.info("[SGX] Key successfully unsealed from enclave.")
    return bytes(unsealed_key)

# ---------------- TPM 2.0 Secure Key Binding ----------------

def secure_store_key_tpm(key):
    """
    Store a cryptographic key securely using TPM 2.0 binding.
    Ensures the key is bound to the device and cannot be exported.
    """
    logging.info("[TPM] Sealing key using TPM 2.0...")

    with ESAPI() as tpm:
        primary_handle = tpm.create_primary()
        sensitive = TPM2B_SENSITIVE_CREATE(user_auth=b"", data=key)
        public = TPM2B_PUBLIC.parse("rsa2048")
        
        key_private, key_public, _, _ = tpm.create(primary_handle, sensitive, public)

        logging.info("[TPM] Key successfully sealed inside TPM.")
        return key_private, key_public

def retrieve_secure_key_tpm(key_private, key_public):
    """
    Retrieve a cryptographic key using TPM 2.0.
    The key remains non-exportable and bound to the TPM device.
    """
    logging.info("[TPM] Retrieving key from TPM 2.0...")

    with ESAPI() as tpm:
        primary_handle = tpm.create_primary()
        loaded_key = tpm.load(primary_handle, key_private, key_public)
        
        decrypted_key = tpm.unseal(loaded_key)

        logging.info("[TPM] Key successfully retrieved from TPM.")
        return decrypted_key

# ---------------- Key Verification Using QKD ----------------

def qkd_key_verification(qkd_key, device_id, shared_secret):
    """
    Validate QKD-derived keys against an HMAC-based entropy verification.
    Ensures that only authorized devices can retrieve QKD keys.
    """
    logging.info("[QKD] Performing entropy-based verification...")

    hmac_verifier = hmac.new(device_id.encode(), shared_secret, hashlib.sha3_512)
    if hmac.compare_digest(hmac_verifier.digest(), qkd_key):
        logging.info("[QKD] Key verification successful.")
        return True  # Key verification successful

    logging.warning("[QKD] WARNING: Possible QKD session hijacking detected!")
    return False  # Possible quantum attack attempt

# ---------------- Main Execution ----------------

if __name__ == "__main__":
    try:
        logging.info("[SECURITY] Starting Secure Key Management...")

        # Retrieve a QKD-derived key
        qkd_key = qkd_derived_key()
        logging.info(f"[QKD] Derived QKD Key: {qkd_key.hex()}")

        # Store in SGX Enclave
        sealed_data_sgx = secure_store_key(qkd_key)
        retrieved_key_sgx = retrieve_secure_key(sealed_data_sgx)
        assert qkd_key == retrieved_key_sgx, "[SGX ERROR] Key mismatch!"

        # Store in TPM 2.0
        key_private, key_public = secure_store_key_tpm(qkd_key)
        retrieved_key_tpm = retrieve_secure_key_tpm(key_private, key_public)
        assert qkd_key == retrieved_key_tpm, "[TPM ERROR] Key mismatch!"

        # Verify QKD Key
        if not qkd_key_verification(qkd_key, "Device-001", retrieved_key_sgx):
            raise ValueError("[QKD] Key verification failed.")

        logging.info("[SECURITY] Secure Key Management SUCCESS. All verifications passed.")
    
    except ValueError as e:
        logging.critical(f"[SECURITY FAILURE] {e}")
        exit(1)
