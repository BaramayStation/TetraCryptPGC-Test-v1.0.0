import hashlib
import time
revoked_keys = set()

def revoke_key(public_key):
    """Revoke a key by adding it to the revocation list."""
    revoked_keys.add(public_key.hex())

def is_key_revoked(public_key):
    """Check if a key is revoked."""
    return public_key.hex() in revoked_keys

class KeyRevocation:
    def __init__(self):
        """Initialize the key revocation system."""
        self.revoked_keys = {}

    def revoke_key(self, public_key, reason="Compromised", expiration=3600):
        """Revoke a public key, marking it invalid for a specific duration."""
        key_hash = hashlib.sha3_512(public_key).hexdigest()
        self.revoked_keys[key_hash] = {"reason": reason, "expires_at": time.time() + expiration}

    def is_revoked(self, public_key):
        """Check if a public key has been revoked."""
        key_hash = hashlib.sha3_512(public_key).hexdigest()
        if key_hash in self.revoked_keys:
            if time.time() > self.revoked_keys[key_hash]["expires_at"]:
                del self.revoked_keys[key_hash]
                return False
            return True
        return False
