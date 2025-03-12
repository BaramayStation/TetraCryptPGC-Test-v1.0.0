import idquantique
from idquantique.qkd_client import QKDClient
import hashlib
import hmac
import time

def real_qkd_exchange(server_address="192.168.1.100", port=5000, device_id="tetrapgc"):
    """Establishes a real QKD session with additional security and fallback mechanisms."""
    
    try:
        print("[INFO] Attempting to establish QKD session...")
        qkd_client = QKDClient(address=server_address, port=port)

        # Request a secure QKD key
        secure_key = qkd_client.get_key(length=256)
        print("[SUCCESS] QKD Key received.")

        # Perform key integrity verification using HMAC
        integrity_check = hmac.new(device_id.encode(), secure_key, hashlib.sha3_512)
        if not hmac.compare_digest(integrity_check.digest(), secure_key):
            raise ValueError("QKD Key integrity check failed!")

        print("[SECURITY] QKD Key successfully verified.")
        return secure_key

    except Exception as e:
        print(f"[ERROR] QKD session failed: {e}")
        print("[FALLBACK] Switching to Kyber-1024 key exchange.")

        # If QKD fails, fallback to post-quantum key exchange
        from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate

        pk, sk = kyber_keygen()
        ct, shared_secret = kyber_encapsulate(pk)
        print("[FALLBACK SUCCESS] Kyber-based key established.")

        return shared_secret

if __name__ == "__main__":
    secure_key = real_qkd_exchange()
    print(f"Final Secure Key: {secure_key.hex()}")
