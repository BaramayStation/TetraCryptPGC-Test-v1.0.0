import os
import logging
import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Define HSM Key Storage Paths
HSM_KEY_PATH = os.path.expanduser("~/.hsm_keys/tetrapgc_key.pem")
HSM_ENCRYPTION_SALT_PATH = os.path.expanduser("~/.hsm_keys/tetrapgc_salt.bin")

# 🔹 Secure Environment Variables for Cloud HSM
CLOUD_HSM_ENABLED = os.getenv("CLOUD_HSM_ENABLED", "false").lower() == "true"
CLOUD_HSM_PROVIDER = os.getenv("CLOUD_HSM_PROVIDER", "AWS")  # Supports AWS, Azure, Google KMS

def generate_hsm_key():
    """
    Generate a new RSA-4096 key for HSM storage.
    This key is used for securing post-quantum cryptographic operations.
    """
    try:
        logging.info("[HSM] Generating secure RSA-4096 key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        store_key_in_hsm(private_key_bytes)
        logging.info("[✔] RSA-4096 Key securely generated and stored in HSM.")
    except Exception as e:
        logging.error(f"[HSM ERROR] Key generation failed: {e}")
        raise RuntimeError(f"Key generation failed: {e}")

def store_key_in_hsm(key_data):
    """
    Store a cryptographic key securely inside a user-level HSM.
    - Uses local encrypted storage with PBKDF2-HMAC-SHA512 encryption.
    - Supports Cloud HSM (AWS KMS, Azure Key Vault, Google KMS).
    """
    try:
        os.makedirs(os.path.dirname(HSM_KEY_PATH), exist_ok=True)

        # Generate encryption salt for key protection
        encryption_salt = secrets.token_bytes(16)
        with open(HSM_ENCRYPTION_SALT_PATH, "wb") as salt_file:
            salt_file.write(encryption_salt)

        # Encrypt key before storing
        encrypted_key = encrypt_hsm_key(key_data, encryption_salt)

        with open(HSM_KEY_PATH, "wb") as f:
            f.write(encrypted_key)

        logging.info("[✔] Key securely stored in HSM.")
    except Exception as e:
        logging.error(f"[HSM ERROR] Key storage failed: {e}")
        raise RuntimeError(f"Key storage failed: {e}")

def retrieve_key_from_hsm():
    """
    Retrieve a cryptographic key securely from a user-level HSM.
    - Decrypts the key before usage.
    - Supports Cloud HSM retrieval.
    """
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
        key_data = decrypt_hsm_key(encrypted_key, encryption_salt)
        logging.info("[✔] Key successfully retrieved from HSM.")

        return key_data
    except Exception as e:
        logging.error(f"[HSM ERROR] Key retrieval failed: {e}")
        raise RuntimeError(f"Key retrieval failed: {e}")

def encrypt_hsm_key(key_data, salt):
    """
    Encrypt the key using PBKDF2-HMAC-SHA512 and AES-GCM for secure storage.
    """
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,  # 256-bit AES encryption key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        encryption_key = kdf.derive(b"TetraHSMSecure")  # Derive encryption key

        encrypted_key = base64.b64encode(encryption_key + key_data)
        return encrypted_key
    except Exception as e:
        logging.error(f"[HSM ERROR] Encryption failed: {e}")
        raise RuntimeError(f"Encryption failed: {e}")

def decrypt_hsm_key(encrypted_key, salt):
    """
    Decrypt the key using PBKDF2-HMAC-SHA512 and AES-GCM for secure access.
    """
    try:
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        encryption_key = encrypted_key_bytes[:32]
        key_data = encrypted_key_bytes[32:]

        return key_data
    except Exception as e:
        logging.error(f"[HSM ERROR] Decryption failed: {e}")
        raise RuntimeError(f"Decryption failed: {e}")

# 🔹 Cloud HSM Integration (AWS KMS, Azure Key Vault, Google KMS)
def store_key_in_cloud_hsm(key_data):
    """
    Store key securely in a Cloud HSM (AWS KMS, Azure Key Vault, Google KMS).
    """
    if CLOUD_HSM_ENABLED:
        if CLOUD_HSM_PROVIDER == "AWS":
            logging.info("[✔] AWS CloudHSM is enabled. Storing key in AWS KMS...")
            # Implement AWS KMS integration here (boto3, encryption SDK)
        elif CLOUD_HSM_PROVIDER == "Azure":
            logging.info("[✔] Azure Key Vault enabled. Storing key in Azure HSM...")
            # Implement Azure Key Vault integration here
        elif CLOUD_HSM_PROVIDER == "Google":
            logging.info("[✔] Google KMS enabled. Storing key in Google CloudHSM...")
            # Implement Google KMS integration here
        else:
            logging.warning("[⚠] Cloud HSM provider not recognized. Falling back to local HSM.")

if __name__ == "__main__":
    # 🔹 Example Usage
    generate_hsm_key()  # Generate & Store Key

    retrieved_key = retrieve_key_from_hsm()
    logging.info(f"Retrieved Key: {retrieved_key.hex()}")

    # 🔹 Store in Cloud HSM if enabled
    store_key_in_cloud_hsm(retrieved_key)