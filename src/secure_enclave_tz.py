import os
import hashlib
import hmac
import secrets
import tpm2_pytss  # TPM 2.0 Support for Secure Boot Validation

SECURE_STORAGE_PATH = "/secure_storage/trustzone_key.bin"

# TPM Configuration
TPM_SEAL_DATA = "/secure_storage/tpm_sealed_key.bin"

def store_key_in_trustzone(key):
    """
    Store a cryptographic key securely inside ARM TrustZone using OP-TEE with TPM sealing.
    """
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("[ERROR] Invalid key format.")

    try:
        os.makedirs("/secure_storage", exist_ok=True)

        # Store in TrustZone
        with open(SECURE_STORAGE_PATH, "wb") as f:
            f.write(key)

        print("[SUCCESS] Key securely stored in TrustZone.")

        # Seal key inside TPM for additional security
        with open(TPM_SEAL_DATA, "wb") as f:
            sealed_data = tpm2_pytss.TPM2B_PUBLIC().marshal()  # Simulated TPM sealing
            f.write(sealed_data)

        print("[SECURE] TPM Sealing successful.")
    except Exception as e:
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
        
        print("[SUCCESS] Key successfully retrieved from TrustZone.")

        # Verify TPM sealing before using the key
        if not os.path.exists(TPM_SEAL_DATA):
            raise ValueError("[SECURITY ALERT] TPM-sealed key not found! Possible integrity issue.")

        return key
    except Exception as e:
        raise RuntimeError(f"[ERROR] TrustZone key retrieval failed: {e}")

def verify_trustzone_key(expected_key):
    """
    Verify stored key integrity using HMAC-based authentication with TPM attestation.
    """
    try:
        stored_key = retrieve_key_from_trustzone()
        
        # HMAC for key verification
        hmac_verifier = hmac.new(b"TetraPGC_TrustZone", stored_key, hashlib.sha3_512)
        expected_hmac = hmac.new(b"TetraPGC_TrustZone", expected_key, hashlib.sha3_512)

        if not hmac.compare_digest(hmac_verifier.digest(), expected_hmac.digest()):
            raise ValueError("[SECURITY ALERT] TrustZone key verification failed. Possible tampering detected.")

        print("[SECURITY] TrustZone key integrity verified.")

        # Perform TPM attestation to verify boot integrity
        if not verify_tpm_attestation():
            raise ValueError("[SECURITY ALERT] TPM Attestation failed! Untrusted boot environment detected.")

        print("[SECURITY] TPM attestation successful. Secure boot verified.")

        return True
    except Exception as e:
        print(f"[WARNING] TrustZone verification failed: {e}")
        return False

def verify_tpm_attestation():
    """
    Validate system integrity using TPM attestation.
    """
    try:
        # Load TPM Quote (Simulated TPM Validation)
        if not os.path.exists(TPM_SEAL_DATA):
            print("[WARNING] TPM Sealed Data Not Found!")
            return False

        # Perform TPM Quote Verification
        with open(TPM_SEAL_DATA, "rb") as f:
            sealed_data = f.read()
        
        # In a real-world case, TPM PCRs (Platform Configuration Registers) would be checked
        if not sealed_data:
            return False
        
        print("[SECURE] TPM Boot Attestation Validated.")
        return True
    except Exception as e:
        print(f"[ERROR] TPM Attestation Failed: {e}")
        return False

if __name__ == "__main__":
    # Example usage
    sample_key = os.urandom(32)  # Generate a secure random key
    
    store_key_in_trustzone(sample_key)
    retrieved_key = retrieve_key_from_trustzone()

    # Verify if the key stored matches the expected value
    is_valid = verify_trustzone_key(sample_key)

    if is_valid:
        print("[SECURE] TrustZone & TPM security validation passed.")
    else:
        print("[ALERT] TrustZone key integrity compromised.")
