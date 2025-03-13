import secrets
import logging
import os
import time
from src.kyber_kem import kyber_keygen, kyber_encapsulate  # ✅ Hybrid Key Exchange Fallback

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Define Secure Entropy Threshold
ENTROPY_THRESHOLD = int(os.getenv("QKD_ENTROPY_THRESHOLD", 192))  # Default: 192 bits
MONITOR_INTERVAL = int(os.getenv("QKD_MONITOR_INTERVAL", 60))  # Check every 60s

class QKDMonitor:
    """Monitors QKD entropy and performs fallback to hybrid PQC if necessary."""

    @staticmethod
    def check_qkd_entropy():
        """
        Analyze QKD entropy level and validate against security threshold.
        Uses simulated entropy measurement (adjustable for future QKD hardware).
        """
        entropy_score = secrets.randbits(256)  # Simulated entropy measurement
        
        logging.info(f"[QKD] Measured entropy: {entropy_score} bits (Threshold: {ENTROPY_THRESHOLD} bits)")

        if entropy_score < ENTROPY_THRESHOLD:
            logging.warning("[SECURITY ALERT] QKD entropy below threshold. Initiating Fallback Mode.")
            return False  # Entropy level insufficient
        
        logging.info("[SUCCESS] QKD entropy meets security standards.")
        return True

    @staticmethod
    def qkd_fallback_key_exchange():
        """Perform Kyber-1024 key exchange as a fallback for QKD failure."""
        logging.warning("[FALLBACK] Switching to Kyber-1024 key exchange...")
        
        # Generate a Kyber key pair
        pk, _ = kyber_keygen()

        # Encapsulate key exchange
        _, shared_secret = kyber_encapsulate(pk)

        logging.info("[FALLBACK SUCCESS] Kyber-1024 shared secret established.")
        return shared_secret

    @staticmethod
    def monitor_qkd():
        """Continuously monitor QKD entropy and initiate fallback if needed."""
        logging.info("[🔍] Starting QKD Monitor Service...")

        while True:
            entropy_valid = QKDMonitor.check_qkd_entropy()

            if not entropy_valid:
                secure_key = QKDMonitor.qkd_fallback_key_exchange()
                logging.info(f"[FALLBACK MODE] New Secure Key Established: {secure_key.hex()}")

            time.sleep(MONITOR_INTERVAL)  # Monitor at regular intervals

# 🔹 Example Execution
if __name__ == "__main__":
    QKDMonitor.monitor_qkd()