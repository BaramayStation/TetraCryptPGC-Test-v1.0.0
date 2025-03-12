import secrets
import logging
import numpy as np
from collections import Counter
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Configure Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Security Thresholds
ENTROPY_THRESHOLD = 128  # Bits of security
FALLBACK_THRESHOLD = 100  # Minimum entropy before switching to hybrid mode

def calculate_shannon_entropy(data):
    """Calculate Shannon entropy of a given QKD key."""
    if not data:
        return 0

    byte_counts = Counter(data)
    total_bytes = len(data)
    
    entropy = -sum((count / total_bytes) * np.log2(count / total_bytes) for count in byte_counts.values())
    return entropy * total_bytes  # Normalize entropy to bits

def entropy_analysis(qkd_key):
    """
    Analyze QKD entropy level and validate against security thresholds.
    Returns True if entropy is sufficient, otherwise triggers fallback.
    """
    entropy_score = calculate_shannon_entropy(qkd_key)
    logging.info(f"[QKD Entropy Check] Entropy Score: {entropy_score} bits")

    if entropy_score < FALLBACK_THRESHOLD:
        logging.critical("[SECURITY ALERT] QKD entropy critically low! Switching to hybrid key exchange.")
        return False
    elif entropy_score < ENTROPY_THRESHOLD:
        logging.warning("[WARNING] QKD entropy below recommended threshold. Consider additional randomness.")
    
    return True

def hybrid_fallback():
    """
    Switches to a post-quantum hybrid fallback (Kyber-1024) if QKD entropy fails.
    """
    logging.warning("[FALLBACK] Engaging hybrid key exchange for security.")
    
    try:
        from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
        
        pk, sk = kyber_keygen()
        ciphertext, shared_secret = kyber_encapsulate(pk)
        logging.info("[FALLBACK SUCCESS] Kyber-1024 key exchange completed.")
        return shared_secret

    except Exception as e:
        logging.critical(f"[FATAL] Hybrid key exchange failed: {e}")
        return None

def derive_final_shared_secret(raw_secret, transcript):
    """Applies HKDF to ensure maximum key randomness."""
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,  # 512-bit final session key
        salt=None,
        info=transcript,
    )
    return hkdf.derive(raw_secret)

# Secure Execution
if __name__ == "__main__":
    test_qkd_key = secrets.token_bytes(32)  # Simulating QKD key retrieval

    if entropy_analysis(test_qkd_key):
        final_key = derive_final_shared_secret(test_qkd_key, b"Secure QKD Session")
        logging.info(f"Final Secure Key: {final_key.hex()}")
    else:
        fallback_key = hybrid_fallback()
        if fallback_key:
            logging.info(f"Fallback Key: {fallback_key.hex()}")
        else:
            logging.critical("[SECURITY FAILURE] No valid key established. System lockdown required.")
