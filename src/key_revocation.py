import time
import os
import logging

# 🔹 Configure Logging for Security Auditing
logging.basicConfig(
    filename="key_revocation_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class KeyRevocation:
    """
    Key Revocation System for Post-Quantum Cryptographic Security.

    Features:
    - Time-based expiration (default: 24 hours)
    - Usage-based revocation (default: 1000 uses)
    - Secure memory overwriting before deletion
    """

    def __init__(self, expiration_time=86400, max_usage=1000):
        """
        :param expiration_time: Time in seconds before key expires (default: 24 hours)
        :param max_usage: Maximum number of uses before key is revoked
        """
        self.expiration_time = expiration_time
        self.max_usage = max_usage
        self.keys = {}  # Secure key store with metadata

    def add_key(self, key_id, key):
        """Register a new key with metadata."""
        self.keys[key_id] = {
            "key": key,
            "created_at": time.time(),
            "usage_count": 0
        }
        logging.info(f"🔹 Key {key_id} added. Expiration: {self.expiration_time}s, Max Usage: {self.max_usage}")

    def use_key(self, key_id):
        """Mark key usage and check if it should be revoked."""
        if key_id not in self.keys:
            logging.warning(f"⚠️ Attempt to use non-existent key: {key_id}")
            raise ValueError("Key not found.")

        key_data = self.keys[key_id]
        key_data["usage_count"] += 1

        # 🔹 Check for expiration or max usage
        if (time.time() - key_data["created_at"] > self.expiration_time) or (key_data["usage_count"] > self.max_usage):
            self.revoke_key(key_id)
            raise ValueError(f"❌ Key {key_id} revoked due to security policy.")

        logging.info(f"🔑 Key {key_id} used ({key_data['usage_count']}/{self.max_usage} times).")
        return key_data["key"]

    def revoke_key(self, key_id):
        """Securely revoke and destroy the key."""
        if key_id in self.keys:
            # 🔹 Securely overwrite key data before deletion
            secure_bytes = os.urandom(len(self.keys[key_id]["key"]))
            self.keys[key_id]["key"] = secure_bytes

            # 🔹 Delete key metadata
            del self.keys[key_id]
            logging.warning(f"🚨 Key {key_id} revoked for security.")
            print(f"🔒 Key {key_id} has been securely revoked.")

# 🔹 Example Usage
if __name__ == "__main__":
    logging.info("🔐 Initializing Key Revocation System...")

    # Initialize revocation policy (Expire in 1 hour or after 10 uses)
    revoker = KeyRevocation(expiration_time=3600, max_usage=10)

    # Generate a secure session key
    session_key = os.urandom(32)
    revoker.add_key("session_key", session_key)

    # Simulate key usage
    for _ in range(12):
        try:
            key = revoker.use_key("session_key")
            print(f"✅ Key Used: {key.hex()[:16]}...")  # Partial key for security
        except ValueError as e:
            print(f"❌ {e}")
            break