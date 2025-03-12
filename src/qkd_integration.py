import hashlib
import hmac
import secrets

def qkd_key_verification(qkd_key, device_id, shared_secret):
    """
    Validate QKD-derived keys against an HMAC-based entropy verification.
    Prevents key injection and tampering attacks.

    Parameters:
    - qkd_key (bytes): The quantum-generated key from QKD.
    - device_id (str): Unique identifier for the device performing verification.
    - shared_secret (bytes): A shared secret key for additional entropy-based verification.

    Returns:
    - bool: True if key verification is successful, False if the key is invalid.
    """

    try:
        if not isinstance(qkd_key, bytes) or not isinstance(shared_secret, bytes):
            raise TypeError("[ERROR] QKD key and shared secret must be byte objects.")

        if len(qkd_key) != len(shared_secret):
            print("[WARNING] Key length mismatch detected.")
            return False

        # HMAC verification using SHA3-512
        hmac_verifier = hmac.new(device_id.encode(), shared_secret, hashlib.sha3_512)

        if hmac.compare_digest(hmac_verifier.digest(), qkd_key):
            print("[SECURITY] QKD Key successfully verified.")
            return True  # Key verification successful

        print("[ALERT] Potential QKD session hijacking detected.")
        return False  # Key does not match, possible attack

    except Exception as e:
        print(f"[ERROR] QKD Key Verification Failed: {e}")
        return False


if __name__ == "__main__":
    # Simulating a QKD key and shared secret for testing
    simulated_qkd_key = secrets.token_bytes(64)  # 512-bit QKD key
    simulated_shared_secret = secrets.token_bytes(64)  # 512-bit shared secret
    device_identifier = "tetrapgc-node1"

    # Validate the QKD key
    verification_result = qkd_key_verification(simulated_qkd_key, device_identifier, simulated_shared_secret)
    print(f"QKD Key Verification Result: {verification_result}")
