import time
import os

class KeyRevocation:
    def __init__(self, expiration_time=86400, max_usage=1000):
        """
        Initialize key revocation with expiration time and max usage.
        :param expiration_time: Time in seconds before key expires (default: 24 hours)
        :param max_usage: Maximum number of uses before key is revoked
        """
        self.expiration_time = expiration_time
        self.max_usage = max_usage
        self.keys = {}  # Store key metadata (created_at, usage_count)

    def add_key(self, key_id, key):
        """Register a new key with metadata"""
        self.keys[key_id] = {
            "key": key,
            "created_at": time.time(),
            "usage_count": 0
        }

    def use_key(self, key_id):
        """Mark key usage and check if it should be revoked"""
        if key_id not in self.keys:
            raise ValueError("Key not found")

        key_data = self.keys[key_id]
        key_data["usage_count"] += 1

        # Check if key should be revoked
        if (time.time() - key_data["created_at"] > self.expiration_time) or (key_data["usage_count"] > self.max_usage):
            self.revoke_key(key_id)

        return key_data["key"]

    def revoke_key(self, key_id):
        """Securely revoke and destroy the key"""
        if key_id in self.keys:
            # Overwrite key data in memory
            os.urandom(len(self.keys[key_id]["key"]))
            del self.keys[key_id]
            print(f"Key {key_id} revoked for security.")

# Example Usage
revoker = KeyRevocation(expiration_time=3600, max_usage=10)  # Expire in 1 hour or after 10 uses
revoker.add_key("session_key", os.urandom(32))
revoker.use_key("session_key")