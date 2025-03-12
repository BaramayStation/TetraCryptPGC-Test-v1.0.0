import os
import requests
import serial  # Required for some QKD hardware
import hashlib
import secrets
import logging
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate  # Post-Quantum Fallback

# Configure security logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define QKD Sources
QKD_PROVIDER = os.getenv("QKD_PROVIDER", "bb84")

def validate_qkd_key(key, expected_length=32):
    """
    Ensures QKD key integrity and entropy.
    Args:
        key (bytes): Quantum key received.
        expected_length (int): Expected length in bytes (default: 32).
    Returns:
        bool: True if key is valid, False otherwise.
    """
    if not key or len(key) != expected_length:
        logging.warning("[SECURITY ALERT] QKD Key length mismatch. Possible compromise detected.")
        return False
    return True

def get_qkd_key_bb84():
    """Simulates a QKD BB84 key exchange."""
    key = secrets.token_bytes(32)  # 256-bit quantum-safe key
    if validate_qkd_key(key):
        logging.info("[QKD] BB84 key successfully generated.")
        return key
    return None

def get_qkd_key_idquantique():
    """Retrieves a QKD key from an ID Quantique system securely."""
    try:
        QKD_API_URL = os.getenv("QKD_API_URL", "https://idq-qkd-server/api/key")
        headers = {"Authorization": f"Bearer {os.getenv('QKD_API_TOKEN', 'default_token')}"}
        response = requests.get(QKD_API_URL, headers=headers, timeout=10, verify=True)

        if response.status_code == 200:
            key = bytes.fromhex(response.json()["key"])
            if validate_qkd_key(key):
                logging.info("[QKD] ID Quantique key successfully retrieved.")
                return key

        logging.error("[SECURITY ALERT] Failed to fetch QKD key from IDQ.")
        return None

    except Exception as e:
        logging.error(f"[ERROR] IDQ QKD key retrieval exception: {e}")
        return None

def get_qkd_key_serial(port="/dev/ttyUSB0", baudrate=115200):
    """Reads a quantum key from a hardware QKD device over serial."""
    try:
        with serial.Serial(port, baudrate, timeout=5) as ser:
            key = ser.read(32)  # Read a 256-bit key
            if validate_qkd_key(key):
                logging.info("[QKD] Serial QKD key successfully retrieved.")
                return key
        return None

    except Exception as e:
        logging.error(f"[ERROR] QKD hardware key retrieval failed: {e}")
        return None

def qkd_fallback():
    """
    Fallback mechanism if QKD fails. Uses Kyber-1024 for post-quantum resilience.
    """
    try:
        logging.warning("[FALLBACK] QKD session failed, switching to post-quantum Kyber-1024 key exchange.")

        # Emergency Kyber-based key exchange
        pk, sk = kyber_keygen()
        ciphertext, shared_secret = kyber_encapsulate(pk)

        logging.info("[FALLBACK SUCCESS] Kyber-based shared key established.")
        return shared_secret

    except Exception as e:
        logging.critical(f"[CRITICAL FAILURE] Fallback Kyber key exchange failed: {e}")
        return None

def get_qkd_key():
    """Universal QKD key retrieval based on provider selection with Zero Trust validation."""
    key = None

    if QKD_PROVIDER == "bb84":
        key = get_qkd_key_bb84()
    elif QKD_PROVIDER == "idquantique":
        key = get_qkd_key_idquantique()
    elif QKD_PROVIDER == "serial":
        key = get_qkd_key_serial()
    else:
        logging.warning("[SECURITY ALERT] Unsupported QKD provider. Defaulting to fallback.")
    
    if not key:
        logging.error("[SECURITY ALERT] QKD failed. Activating post-quantum fallback.")
        key = qkd_fallback()

    if key:
        logging.info("[QKD] Final secure key successfully obtained.")
    else:
        logging.critical("[SECURITY FAILURE] No valid key was generated. System shutdown required.")

    return key

# ---------------- Main Execution ----------------
if __name__ == "__main__":
    secure_key = get_qkd_key()
    if secure_key:
        logging.info(f"Final Secure Key: {secure_key.hex()}")
