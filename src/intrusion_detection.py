import hashlib
import time
import logging

# Setup logging
logging.basicConfig(filename="intrusion.log", level=logging.INFO)

class IntrusionDetection:
    """Detects cryptographic anomalies & possible MITM attacks."""

    def __init__(self):
        self.previous_signatures = {}

    def detect_anomalies(self, shared_secret, signature, peer):
        """Check if the shared secret has changed unexpectedly."""
        hash_secret = hashlib.sha256(shared_secret).hexdigest()
        if peer in self.previous_signatures:
            if self.previous_signatures[peer] != hash_secret:
                logging.warning(f"Potential MITM detected! Peer: {peer}")
                return False
        self.previous_signatures[peer] = hash_secret
        return True

# Initialize IDS
IDS = IntrusionDetection()
