import os
import secrets
import hashlib
import json
import logging
from datetime import datetime
from shamir_secret_sharing import generate_shares, reconstruct_secret

# Enable structured logging for security audits
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class KeyTransparency:
    """
    Implements a Key Transparency Log to track MPC key operations.
    """

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

        logging.info("[✔] Key Operation Logged: %s", action)

class MPCKeySharing:
    """
    Implements Multi-Party Computation (MPC) for secure key sharing.
    """

    def __init__(self, threshold=3, total_shares=5):
        """
        Initialize MPC key sharing.
        Args:
            threshold (int): Minimum shares required to reconstruct the key.
            total_shares (int): Total number of shares to distribute.
        """
        if threshold > total_shares:
            raise ValueError("Threshold must be <= total shares.")
        
        self.threshold = threshold
        self.total_shares = total_shares
        self.transparency_log = KeyTransparency()

    def generate_mpc_key_shares(self):
        """
        Generate a secret key and split it into MPC key shares.
        Returns:
            (list): List of key shares.
        """
        secret_key = secrets.token_bytes(32)  # 256-bit secret key
        shares = generate_shares(secret_key, self.threshold, self.total_shares)

        # Log Key Generation
        self.transparency_log.log_key_operation("key_generated", secret_key)
        return shares

    def reconstruct_mpc_key(self, shares):
        """
        Reconstruct the original secret key using a threshold number of shares.
        Args:
            shares (list): List of key shares.
        Returns:
            (bytes): Reconstructed secret key.
        """
        if len(shares) < self.threshold:
            raise ValueError("Not enough shares to reconstruct the key.")

        reconstructed_key = reconstruct_secret(shares)

        # Log Key Reconstruction
        self.transparency_log.log_key_operation("key_reconstructed", reconstructed_key)
        return reconstructed_key

if __name__ == "__main__":
    # Initialize MPC Key Sharing with (threshold=3, total_shares=5)
    mpc = MPCKeySharing(threshold=3, total_shares=5)

    # Step 1: Generate Key Shares
    key_shares = mpc.generate_mpc_key_shares()
    print(f"MPC Key Shares: {key_shares}")

    # Step 2: Reconstruct Secret with 3 out of 5 Shares
    reconstructed_key = mpc.reconstruct_mpc_key(key_shares[:3])
    print(f"Reconstructed Key: {reconstructed_key.hex()}")
