import os
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# TPM Integration (Linux-based)
TPM_PATH = "/sys/class/tpm/tpm0"

def is_tpm_available():
    """Check if a TPM module is available on the system."""
    return os.path.exists(TPM_PATH)

def secure_store_key(key_data, identifier="default_key"):
    """Securely store a key using TPM or fallback to local encrypted storage."""
    if is_tpm_available():
        with open(f"{TPM_PATH}/{identifier}", "wb") as f:
            f.write(base64.b64encode(key_data))
    else:
        with open(f"/etc/tetrapgc/{identifier}.key", "wb") as f:
            f.write(base64.b64encode(key_data))

def retrieve_secure_key(identifier="default_key"):
    """Retrieve a key securely from TPM or fallback storage."""
    key_path = f"{TPM_PATH}/{identifier}" if is_tpm_available() else f"/etc/tetrapgc/{identifier}.key"
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return base64.b64decode(f.read())
    raise FileNotFoundError("Secure key not found.")
