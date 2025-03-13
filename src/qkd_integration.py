import os
import requests
import secrets
import serial  # Required for serial-based QKD
import hashlib
import hmac
import logging

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Define Available QKD Providers
QKD_PROVIDER = os.getenv("QKD_PROVIDER", "bb84")  # Default to BB84

class QKDIntegration:
    """
    Secure Quantum Key Distribution (QKD) Integration
    - Supports: BB84 (Simulated), ID Quantique, Serial-based QKD
    - Implements HMAC-based integrity verification
    """

    @staticmethod
    def get_qkd_key():
        """Retrieve a QKD key dynamically based on provider selection."""
        try:
            logging.info(f"🔹 [QKD] Retrieving key using {QKD_PROVIDER} provider...")

            if QKD_PROVIDER == "bb84":
                return QKDIntegration.get_qkd_key_bb84()
            elif QKD_PROVIDER == "idquantique":
                return QKDIntegration.get_qkd_key_idquantique()
            elif QKD_PROVIDER == "serial":
                return QKDIntegration.get_qkd_key_serial()
            else:
                raise ValueError(f"Unsupported QKD provider: {QKD_PROVIDER}")

        except Exception as e:
            logging.error(f"❌ [ERROR] QKD key retrieval failed: {e}")
            raise

    @staticmethod
    def get_qkd_key_bb84():
        """Simulated BB84 QKD key generation (secure random bytes)."""
        logging.info("🔹 [BB84] Generating simulated QKD key...")
        return secrets.token_bytes(32)  # Simulated 256-bit QKD key

    @staticmethod
    def get_qkd_key_idquantique():
        """Retrieve QKD key from an ID Quantique system."""
        try:
            qkd_api_url = os.getenv("QKD_API_URL", "https://idq-qkd-server/api/key")
            logging.info(f"🔹 [IDQ] Fetching QKD key from {qkd_api_url}...")

            response = requests.get(qkd_api_url, timeout=10)
            if response.status_code == 200:
                key = bytes.fromhex(response.json()["key"])
                logging.info("✅ [SUCCESS] ID Quantique QKD key retrieved.")
                return key

            raise ConnectionError("Failed to fetch QKD key from IDQ.")

        except Exception as e:
            logging.error(f"❌ [ERROR] IDQ QKD key retrieval failed: {e}")
            raise

    @staticmethod
    def get_qkd_key_serial(port="/dev/ttyUSB0", baudrate=115200):
        """Retrieve a QKD key from a hardware device over a serial connection."""
        try:
            logging.info(f"🔹 [Serial QKD] Connecting to {port} at {baudrate} baud...")
            with serial.Serial(port, baudrate, timeout=5) as ser:
                key = ser.read(32)  # Read 256-bit QKD key
                logging.info("✅ [SUCCESS] Serial-based QKD key retrieved.")
                return key

        except Exception as e:
            logging.error(f"❌ [ERROR] Serial QKD key retrieval failed: {e}")
            raise

    @staticmethod
    def verify_qkd_key(qkd_key, device_id, shared_secret):
        """Verify QKD key integrity using HMAC authentication."""
        logging.info("🔹 [QKD] Verifying key integrity with HMAC...")
        hmac_verifier = hmac.new(device_id.encode(), shared_secret, hashlib.sha3_512)
        is_valid = hmac.compare_digest(hmac_verifier.digest(), qkd_key)

        if is_valid:
            logging.info("✅ [SECURITY] QKD Key integrity verified successfully.")
        else:
            logging.warning("🚨 [SECURITY ALERT] QKD Key integrity verification failed!")

        return is_valid

# 🔹 Example Execution
if __name__ == "__main__":
    try:
        device_id = "tetrapgc"
        shared_secret = secrets.token_bytes(32)  # Simulated shared secret

        # Retrieve QKD key
        qkd_key = QKDIntegration.get_qkd_key()

        # Verify the retrieved QKD key
        valid = QKDIntegration.verify_qkd_key(qkd_key, device_id, shared_secret)

        print(f"🔑 Final Secure QKD Key: {qkd_key.hex()}")
        print(f"✅ Integrity Check: {'Passed' if valid else 'Failed'}")

    except Exception as e:
        print(f"❌ QKD Integration Failed: {e}")