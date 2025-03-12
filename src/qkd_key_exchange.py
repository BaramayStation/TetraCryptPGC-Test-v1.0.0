import os
import logging
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate

# Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def qkd_fallback_key_exchange():
    """Perform Kyber-1024 key exchange as a fallback for QKD."""
    logging.info("[FALLBACK] Initiating Kyber-1024 key exchange...")

    # Generate a Kyber key pair
    pk, _ = kyber_keygen()

    # Encapsulate key exchange
    _, shared_secret = kyber_encapsulate(pk)

    logging.info("[FALLBACK SUCCESS] Kyber-1024 shared secret established.")
    return shared_secret

def hybrid_key_exchange():
    """Perform a hybrid key exchange using QKD and Kyber-1024 as fallback."""
    try:
        logging.info("[QKD] Attempting QKD key retrieval...")
        
        # Retrieve QKD key securely (this function should be defined elsewhere)
        qkd_key = get_qkd_key()
        
        logging.info("[QKD SUCCESS] Quantum key successfully obtained.")
        return qkd_key

    except Exception as e:
        logging.error(f"[ERROR] QKD key retrieval failed: {e}")
        logging.warning("[FALLBACK] Switching to Kyber-1024 key exchange.")

        return qkd_fallback_key_exchange()

if __name__ == "__main__":
    secure_key = hybrid_key_exchange()
    logging.info(f"Final Secure Key: {secure_key.hex()}")
