import hashlib
import json
from datetime import datetime

class KeyTransparency:
    def __init__(self, log_file="key_transparency.log"):
        """Initialize a log file for tracking key operations."""
        self.log_file = log_file

    def log_key_operation(self, action, key):
        """Log key actions such as generation, sharing, and revocation."""
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "key_fingerprint": hashlib.sha256(key).hexdigest()
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record) + "\n")
