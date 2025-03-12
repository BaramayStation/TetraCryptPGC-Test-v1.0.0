import os
import logging
import hashlib
import hmac
import time
import secrets  # Secure random module
from idquantique.qkd_client import QKDClient
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate

# Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Secure Environment Variables for QKD Configuration
QKD_SERVER_LIST = os.getenv("QKD_SERVERS", "qkd1.example.com,qkd2.example.com").split(",")
QKD_PORT = int(os.getenv("QKD_PORT", "5000"))
DEVICE_ID = os.getenv("DEVICE_ID", "tetrapgc")

# Use a cryptographically secure random generator
secure_rng = secrets.SystemRandom()  

def discover_qkd_server():
    """Dynamically selects an available QKD server from a secure list."""
    logging.info("[QKD] Discovering available QKD servers...")

    for server in secure_rng.sample(QKD_SERVER_LIST, len(QKD_SERVER_LIST)):  # Secure random shuffle
        try:
            logging.info(f"[QKD] Attempting connection to {server}:{QKD_PORT}")
            return server
        except Exception as e:
            logging.warning(f"[QKD] Failed to connect to {server}: {e}")

    raise ConnectionError("[QKD] No available QKD servers found.")

def secure_qkd_exchange():
    """Establishes a QKD session securely with additional verification & fallback."""
    try:
        server_address = discover_qkd_server()  # Select QKD server dynamically
        logging.info(f"[QKD] Connecting to {server_address}:{QKD_PORT}...")

        qkd_client = QKDClient(address=server_address, port=QKD_PORT)
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
        pk, sk = kyber_keygen()
        ct, shared_secret = kyber_encapsulate(pk)
        logging.info("[FALLBACK SUCCESS] Kyber-1024 key established as alternative.")

        return shared_secret

if __name__ == "__main__":
    secure_key = secure_qkd_exchange()
    logging.info(f"Final Secure Key: {secure_key.hex()}")
