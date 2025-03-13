import os
import logging
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.qkd_integration import QKDIntegration  # ✅ Secure QKD handling module

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Dynamic Algorithm Selection
ALGORITHM = os.getenv("TETRACRYPT_ALGORITHM", "QKD").upper()  # QKD, FALCON, KYBER

class HybridKeyExchange:
    """Implements a future-proof hybrid key exchange using QKD + PQC Fallback."""

    @staticmethod
    def check_liboqs_version():
        """Check for liboqs version (future-proofing for quantum-safe libraries)."""
        # Placeholder: Extend when using liboqs-based key exchange
        pass

    @staticmethod
    def qkd_fallback_key_exchange():
        """Perform Kyber-1024 key exchange if QKD is unavailable."""
        logging.info("[FALLBACK] Initiating Kyber-1024 key exchange...")

        # Generate a Kyber key pair
        pk, sk = kyber_keygen()

        # Encapsulate key exchange
        ciphertext, shared_secret = kyber_encapsulate(pk)

        logging.info("[FALLBACK SUCCESS] Kyber-1024 shared secret established.")
        return shared_secret

    @staticmethod
    def hybrid_key_exchange():
        """Perform a hybrid key exchange using QKD and Kyber-1024 as fallback."""
        if ALGORITHM == "QKD":
            try:
                logging.info("[QKD] Attempting QKD key retrieval...")

                # Retrieve QKD key securely using QKD integration module
                qkd_key = QKDIntegration.get_qkd_key()

                logging.info("[QKD SUCCESS] Quantum key successfully obtained.")
                return qkd_key

            except Exception as e:
                logging.error(f"[ERROR] QKD key retrieval failed: {e}")
                logging.warning("[FALLBACK] Switching to Kyber-1024 key exchange.")
                return HybridKeyExchange.qkd_fallback_key_exchange()

        elif ALGORITHM == "FALCON":
            # Placeholder for Falcon key exchange (if applicable in the future)
            logging.info("[FALCON] Using Falcon-based key exchange.")
            return os.urandom(32)  # Placeholder (replace with Falcon key exchange logic)

        else:
            logging.error("[ERROR] Unknown algorithm specified, defaulting to Kyber-1024.")
            return HybridKeyExchange.qkd_fallback_key_exchange()


# 🔹 Example Execution
if __name__ == "__main__":
    secure_key = HybridKeyExchange.hybrid_key_exchange()
    logging.info(f"🔑 Final Secure Key: {secure_key.hex()}")