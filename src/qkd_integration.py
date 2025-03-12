import hashlib
import hmac
import secrets

def qkd_key_verification(qkd_key, device_id, shared_secret):
    """Validate QKD-derived keys against an HMAC-based entropy verification."""
    hmac_verifier = hmac.new(device_id.encode(), shared_secret, hashlib.sha3_512)
    if hmac.compare_digest(hmac_verifier.digest(), qkd_key):
        return True  # Key verification successful
    return False  # Potential QKD session hijacking