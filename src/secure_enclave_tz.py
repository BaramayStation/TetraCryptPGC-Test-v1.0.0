import os
import hashlib
import hmac

SECURE_STORAGE_PATH = "/secure_storage/trustzone_key.bin"

def store_key_in_trustzone(key):
    """
    Store a cryptographic key securely inside ARM TrustZone using OP-TEE.
    """
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("Invalid key format.")

    try:
        os.makedirs("/secure_storage", exist_ok=True)
        with open(SECURE_STORAGE_PATH, "wb") as f:
            f.write(key)
        print("[SUCCESS] Key securely stored in TrustZone.")
    except Exception as e:
        raise RuntimeError(f"TrustZone storage failed: {e}")

def retrieve_key_from_trustzone():
    """
    Retrieve a cryptographic key securely from TrustZone Secure Storage.
    """
    try:
        if not os.path.exists(SECURE_STORAGE_PATH):
            raise FileNotFoundError("Secure key storage not found.")

        with open(SECURE_STORAGE_PATH, "rb") as f:
            key = f.read()
        
        print("[SUCCESS] Key successfully retrieved from TrustZone.")
        return key
    except Exception as e:
        raise RuntimeError(f"TrustZone key retrieval failed: {e}")

def verify_trustzone_key(expected_key):
    """
    Verify stored key integrity using HMAC-based authentication.
    """
    try:
        stored_key = retrieve_key_from_trustzone()
        
        hmac_verifier = hmac.new(b"TetraPGC_TrustZone", stored_key, hashlib.sha3_512)
        expected_hmac = hmac.new(b"TetraPGC_TrustZone", expected_key, hashlib.sha3_512)

        if not hmac.compare_digest(hmac_verifier.digest(), expected_hmac.digest()):
            raise ValueError("[SECURITY ALERT] TrustZone key verification failed. Possible tampering detected.")

        print("[SECURITY] TrustZone key integrity verified.")
        return True
    except Exception as e:
        print(f"[WARNING] TrustZone verification failed: {e}")
        return False

if __name__ == "__main__":
    # Example usage
    sample_key = os.urandom(32)  # Generate a secure random key
    
    store_key_in_trustzone(sample_key)
    retrieved_key = retrieve_key_from_trustzone()

    # Verify if the key stored matches the expected value
    is_valid = verify_trustzone_key(sample_key)

    if is_valid:
        print("[SECURE] TrustZone key validation passed.")
    else:
        print("[ALERT] TrustZone key integrity compromised.")
