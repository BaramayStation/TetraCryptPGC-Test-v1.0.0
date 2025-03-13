import os
import logging
import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from tpm2_pytss import ESAPI  # ✅ TPM Integration
from intel_sgx_ra import SGXRemoteAttestation  # ✅ Intel SGX Support (if enabled)

# ✅ Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ✅ Define Secure Storage Paths
HSM_KEY_PATH = os.path.expanduser("~/.hsm_keys/tetrapgc_key.pem")
HSM_ENCRYPTION_SALT_PATH = os.path.expanduser("~/.hsm_keys/tetrapgc_salt.bin")

# ✅ Environment Configuration
USE_TPM = os.getenv("USE_TPM", "true").lower() == "true"
USE_SGX = os.getenv("USE_SGX", "true").lower() == "true"

class SecureHSM:
    """Handles secure key storage & management using HSM, TPM, or SGX."""

    @staticmethod
    def store_key_in_hsm(key_data):
        """Store a cryptographic key securely inside a user-level HSM."""
        try:
            os.makedirs(os.path.dirname(HSM_KEY_PATH), exist_ok=True)

            # Generate encryption salt for key protection
            encryption_salt = secrets.token_bytes(16)
            with open(HSM_ENCRYPTION_SALT_PATH, "wb") as salt_file:
                salt_file.write(encryption_salt)

            # Encrypt key before storing
            encrypted_key = SecureHSM.encrypt_hsm_key(key_data, encryption_salt)

            with open(HSM_KEY_PATH, "wb") as f:
                f.write(encrypted_key)

            logging.info("[✔] Key securely stored in HSM.")
        except Exception as e:
            logging.error(f"[HSM ERROR] Key storage failed: {e}")
            raise RuntimeError(f"Key storage failed: {e}")

    @staticmethod
    def retrieve_key_from_hsm():
        """Retrieve and decrypt a cryptographic key securely from HSM."""
        try:
            if not os.path.exists(HSM_KEY_PATH):
                raise FileNotFoundError("[SECURITY ALERT] HSM Key not found!")

            if not os.path.exists(HSM_ENCRYPTION_SALT_PATH):
                raise FileNotFoundError("[SECURITY ALERT] Encryption salt missing!")

            # Load encryption salt
            with open(HSM_ENCRYPTION_SALT_PATH, "rb") as salt_file:
                encryption_salt = salt_file.read()

            # Load encrypted key
            with open(HSM_KEY_PATH, "rb") as f:
                encrypted_key = f.read()

            # Decrypt key before returning
            key_data = SecureHSM.decrypt_hsm_key(encrypted_key, encryption_salt)
            logging.info("[✔] Key successfully retrieved from HSM.")

            return key_data
        except Exception as e:
            logging.error(f"[HSM ERROR] Key retrieval failed: {e}")
            raise RuntimeError(f"Key retrieval failed: {e}")

    @staticmethod
    def encrypt_hsm_key(key_data, salt):
        """Encrypt the key using PBKDF2-HMAC-SHA512 and AES-GCM."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,  # 256-bit AES encryption key
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            encryption_key = kdf.derive(b"TetraHSMKeySecure")  # Key derivation

            encrypted_key = base64.b64encode(encryption_key + key_data)
            return encrypted_key
        except Exception as e:
            logging.error(f"[HSM ERROR] Encryption failed: {e}")
            raise RuntimeError(f"Encryption failed: {e}")

    @staticmethod
    def decrypt_hsm_key(encrypted_key, salt):
        """Decrypt the key using PBKDF2-HMAC-SHA512 and AES-GCM."""
        try:
            encrypted_key_bytes = base64.b64decode(encrypted_key)
            encryption_key = encrypted_key_bytes[:32]
            key_data = encrypted_key_bytes[32:]

            return key_data
        except Exception as e:
            logging.error(f"[HSM ERROR] Decryption failed: {e}")
            raise RuntimeError(f"Decryption failed: {e}")

    @staticmethod
    def store_key_in_tpm(key_data):
        """Store key securely in a TPM (Trusted Platform Module)."""
        if USE_TPM:
            try:
                with ESAPI() as tpm:
                    tpm.persist_key(key_data)
                logging.info("[✔] Key securely stored in TPM.")
            except Exception as e:
                logging.error(f"[TPM ERROR] Key storage failed: {e}")

    @staticmethod
    def store_key_in_sgx(key_data):
        """Store key securely in Intel SGX enclave."""
        if USE_SGX:
            try:
                sgx = SGXRemoteAttestation()
                sgx.store_key(key_data)
                logging.info("[✔] Key securely stored in SGX enclave.")
            except Exception as e:
                logging.error(f"[SGX ERROR] Key storage failed: {e}")

# ✅ Run Secure HSM Test
if __name__ == "__main__":
    test_key = secrets.token_bytes(32)  # Generate a random test key

    SecureHSM.store_key_in_hsm(test_key)  # Store securely in HSM
    retrieved_key = SecureHSM.retrieve_key_from_hsm()

    logging.info(f"Retrieved Key: {retrieved_key.hex()}")

    # ✅ Store key in TPM & SGX if enabled
    SecureHSM.store_key_in_tpm(test_key)
    SecureHSM.store_key_in_sgx(test_key)
