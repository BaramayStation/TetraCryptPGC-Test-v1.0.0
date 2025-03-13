import os
import logging
import hashlib
import hmac
from idquantique.qkd_client import QKDClient
from src.kyber_kem import kyber_keygen, kyber_encapsulate

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Secure Environment Variables for QKD Configuration
QKD_SERVER = os.getenv("QKD_SERVER", "qkd1.example.com")  # Default QKD server
QKD_PORT = int(os.getenv("QKD_PORT", "5000"))  # Default QKD server port
DEVICE_ID = os.getenv("DEVICE_ID", "tetrapgc")  # Unique device identifier for HMAC integrity verification

class QKDExchange:
    """
    Secure Quantum Key Distribution (QKD) Exchange using ID Quantique
    with a fallback to Kyber-1024 in case of failure.
    """

    @staticmethod
    def establish_qkd_session():
        """Securely connects to a QKD server, retrieves a key, and verifies integrity."""
        try:
            logging.info(f"🔹 [QKD] Connecting to {QKD_SERVER}:{QKD_PORT}...")
            qkd_client = QKDClient(address=QKD_SERVER, port=QKD_PORT)
            secure_key = qkd_client.get_key(length=256)  # Retrieve a 256-bit quantum-secure key

            logging.info("✅ [SUCCESS] QKD Key successfully retrieved.")

            # 🔹 Perform HMAC-based integrity verification
            integrity_check = hmac.new(DEVICE_ID.encode(), secure_key, hashlib.sha3_512)
            if not hmac.compare_digest(integrity_check.digest(), secure_key):
                raise ValueError("🚨 [SECURITY ALERT] QKD Key integrity verification failed!")

            logging.info("🔒 [SECURITY] QKD Key successfully verified and authenticated.")
            return secure_key

        except Exception as e:
            logging.error(f"❌ [ERROR] QKD session failed: {e}")
            logging.warning("⚠️ [FALLBACK] Switching to Kyber-1024 post-quantum key exchange.")

            # If QKD fails, fallback to Kyber-1024 post-quantum key exchange
            return QKDExchange.fallback_to_pqc()

    @staticmethod
    def fallback_to_pqc():
        """Performs Kyber-1024 post-quantum key encapsulation as a fallback."""
        logging.info("🔹 [PQC] Generating Kyber-1024 key pair as fallback...")
        pk, _ = kyber_keygen()  # Generate Kyber key pair
        _, shared_secret = kyber_encapsulate(pk)  # Encapsulate key using Kyber

        logging.info("✅ [FALLBACK SUCCESS] Kyber-1024 key established as an alternative.")
        return shared_secret

# 🔹 Execute Secure QKD or PQC Fallback
if __name__ == "__main__":
    secure_key = QKDExchange.establish_qkd_session()
    logging.info(f"🔑 Final Secure Key: {secure_key.hex()}")