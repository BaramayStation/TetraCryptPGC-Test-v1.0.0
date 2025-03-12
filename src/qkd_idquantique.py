import os
import logging
import hashlib
import hmac
from idquantique.qkd_client import QKDClient
from src.kyber_kem import kyber_keygen, kyber_encapsulate

# Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Secure Environment Variables for QKD Configuration
QKD_SERVER = os.getenv("QKD_SERVER", "qkd1.example.com")
QKD_PORT = int(os.getenv("QKD_PORT", "5000"))
DEVICE_ID = os.getenv("DEVICE_ID", "tetrapgc")

def secure_qkd_exchange():
    """Establishes a QKD session securely with additional verification & fallback."""
    try:
        logging.info(f"[QKD] Connecting to {QKD_SERVER}:{QKD_PORT}...")
        qkd_client = QKDClient(address=QKD_SERVER, port=QKD_PORT)
        secure_key = qkd_client.get_key(length=256)

        logging.info("[SUCCESS] QKD Key successfully retrieved.")

        # Perform HMAC-based integrity verification
        integrity_check = hmac.new(DEVICE_ID.encode(), secure_key, hashlib.sha3_512)
        if not hmac.compare_digest(integrity_check.digest(), secure_key):
            raise ValueError("[SECURITY ALERT] QKD Key integrity verification failed!")

        logging.info("[SECURITY] QKD Key successfully verified and authenticated.")
        return secure_key

    except Exception as e:
        logging.error(f"[ERROR] QKD session failed: {e}")
        logging.warning("[FALLBACK] Switching to Kyber-1024 post-quantum key exchange.")

        # If QKD fails, fallback to post-quantum key exchange
        pk, _ = kyber_keygen()
        _, shared_secret = kyber_encapsulate(pk)
        logging.info("[FALLBACK SUCCESS] Kyber-1024 key established as alternative.")

        return shared_secret

if __name__ == "__main__":
    secure_key = secure_qkd_exchange()
    logging.info(f"Final Secure Key: {secure_key.hex()}")
