import os
import requests
import secrets
import hashlib
import hmac
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate

QKD_PROVIDER = os.getenv("QKD_PROVIDER", "idquantique")

def get_qkd_key():
    """Retrieve a quantum-generated key from QKD hardware or a trusted API."""
    try:
        if QKD_PROVIDER == "idquantique":
            return get_qkd_key_idquantique()
        elif QKD_PROVIDER == "bb84":
            return get_qkd_key_bb84()
        else:
            raise ValueError("Unsupported QKD provider.")
    except Exception as e:
        print(f"[ERROR] QKD key retrieval failed: {e}")
        print("[FALLBACK] Using Kyber-1024 post-quantum key exchange.")
        return pqc_fallback_key_exchange()

def get_qkd_key_idquantique():
    """Fetch a secure QKD key from an ID Quantique QKD system."""
    QKD_API_URL = os.getenv("QKD_API_URL", "https://qkd-server/api/key")
    response = requests.get(QKD_API_URL, timeout=10)
    if response.status_code == 200:
        return bytes.fromhex(response.json()["key"])
    raise ConnectionError("Failed to fetch QKD key.")

def get_qkd_key_bb84():
    """Simulate a QKD BB84 key exchange."""
    return secrets.token_bytes(32)

def pqc_fallback_key_exchange():
    """Use Kyber-1024 if QKD is unavailable."""
    pk, sk = kyber_keygen()
    ciphertext, shared_secret = kyber_encapsulate(pk)
    return shared_secret

if __name__ == "__main__":
    key = get_qkd_key()
    print(f"QKD Secure Key: {key.hex()}")
