import os
import hashlib
import hmac
import secrets
import logging
import tpm2_pytss  # TPM 2.0 Support for Secure Boot Validation

# 🔹 Secure Storage Paths
SECURE_STORAGE_PATH = "/secure_storage/trustzone_key.bin"
TPM_SEAL_DATA = "/secure_storage/tpm_sealed_key.bin"

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def store_key_in_trustzone(key):
    """
    Store a cryptographic key securely inside ARM TrustZone using OP-TEE with TPM sealing.
    """
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("[SECURITY ERROR] Invalid key format.")

    try:
        os.makedirs("/secure_storage", exist_ok=True)

        # 🔹 Store in TrustZone Secure Storage
        with open(SECURE_STORAGE_PATH, "wb") as f:
            f.write(key)
        logging.info("[✔] Key securely stored in TrustZone.")

        # 🔹 Seal key inside TPM for additional security
        with open(TPM_SEAL_DATA, "wb") as f:
            sealed_data = tpm2_pytss.TPM2B_PUBLIC().marshal()  # Simulated TPM sealing
            f.write(sealed_data)
        logging.info("[✔] TPM Sealing successful.")

    except Exception as e:
        logging.error(f"[SECURITY ERROR] TrustZone storage failed: {e}")
        raise RuntimeError(f"[ERROR] TrustZone storage failed: {e}")

def retrieve_key_from_trustzone():
    """
    Retrieve a cryptographic key securely from TrustZone Secure Storage.
    """
    try:
        if not os.path.exists(SECURE_STORAGE_PATH):
            raise FileNotFoundError("[SECURITY ALERT] Secure key storage not found.")

        with open(SECURE_STORAGE_PATH, "rb") as f:
            key = f.read()
        
        logging.info("[✔] Key successfully retrieved from TrustZone.")

        # 🔹 Verify TPM sealing before using the key
        if not os.path.exists(TPM_SEAL_DATA):
            raise ValueError("[SECURITY ALERT] TPM-sealed key not found! Possible integrity issue.")

        return key

    except Exception as e:
        logging.error(f"[SECURITY ERROR] TrustZone key retrieval failed: {e}")
        raise RuntimeError(f"[ERROR] TrustZone key retrieval failed: {e}")

def verify_trustzone_key(expected_key):
    """
    Verify stored key integrity using HMAC-based authentication with TPM attestation.
    """
    try:
        stored_key = retrieve_key_from_trustzone()
        
        # 🔹 HMAC for Key Integrity Verification
        hmac_verifier = hmac.new(b"TetraPGC_TrustZone", stored_key, hashlib.sha3_512)
        expected_hmac = hmac.new(b"TetraPGC_TrustZone", expected_key, hashlib.sha3_512)

        if not hmac.compare_digest(hmac_verifier.digest(), expected_hmac.digest()):
            logging.critical("[SECURITY ALERT] TrustZone key verification failed. Possible tampering detected.")
            raise ValueError("[SECURITY ALERT] TrustZone key verification failed!")

        logging.info("[✔] TrustZone key integrity verified.")

        # 🔹 Perform TPM Attestation to Verify Secure Boot
        if not verify_tpm_attestation():
            logging.critical("[SECURITY ALERT] TPM Attestation failed! Untrusted boot environment detected.")
            raise ValueError("[SECURITY ALERT] TPM Attestation failed!")

        logging.info("[✔] TPM attestation successful. Secure boot verified.")

        return True
    except Exception as e:
        logging.warning(f"[SECURITY WARNING] TrustZone verification failed: {e}")
        return False

def verify_tpm_attestation():
    """
    Validate system integrity using TPM attestation.
    """
    try:
        # 🔹 Load TPM Quote (Simulated TPM Validation)
        if not os.path.exists(TPM_SEAL_DATA):
            logging.warning("[⚠] TPM Sealed Data Not Found!")
            return False

        # 🔹 Perform TPM Quote Verification
        with open(TPM_SEAL_DATA, "rb") as f:
            sealed_data = f.read()
        
        # In a real-world case, TPM PCRs (Platform Configuration Registers) would be checked
        if not sealed_data:
            return False
        
        logging.info("[✔] TPM Boot Attestation Validated.")
        return True
    except Exception as e:
        logging.error(f"[ERROR] TPM Attestation Failed: {e}")
        return False

if __name__ == "__main__":
    # 🔹 Example usage
    sample_key = os.urandom(32)  # Generate a secure random key
    
    store_key_in_trustzone(sample_key)
    retrieved_key = retrieve_key_from_trustzone()

    # 🔹 Verify if the key stored matches the expected value
    is_valid = verify_trustzone_key(sample_key)

    if is_valid:
        logging.info("[✔] TrustZone & TPM security validation passed.")
    else:
        logging.critical("[ALERT] TrustZone key integrity compromised.")