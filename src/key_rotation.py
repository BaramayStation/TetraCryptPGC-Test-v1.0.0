import time
import hashlib
from src.kyber_kem import kyber_keygen
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import time

ROTATION_INTERVAL = 30 * 24 * 60 * 60  # 30 days

def should_rotate(last_rotation_time):
    """Check if key rotation is needed based on time elapsed."""
    return (time.time() - last_rotation_time) > ROTATION_INTERVAL

class KeyRotation:
    def __init__(self, rotation_interval=3600):
        """Initialize key rotation with a defined interval (default: 1 hour)."""
        self.rotation_interval = rotation_interval
        self.current_key = None
        self.last_rotation = time.time()

    def rotate_keys(self):
        """Generate new ephemeral keys and derive fresh session keys."""
        pk, sk = kyber_keygen()
        raw_key_material = hashlib.sha3_512(pk + sk).digest()

        session_key = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=None,
            info=b"Session Key Rotation",
        ).derive(raw_key_material)

        self.current_key = session_key
        self.last_rotation = time.time()
        return session_key

    def check_rotation(self):
        """Check if key rotation is required and update keys if necessary."""
        if time.time() - self.last_rotation > self.rotation_interval:
            return self.rotate_keys()
        return self.current_key
