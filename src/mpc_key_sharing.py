import secrets
import hashlib
from typing import List, Tuple
from shamir import Shamir  # Uses a proper threshold-based secret sharing library

class MPCKeySharing:
    """
    Secure Multi-Party Computation (MPC) Key Sharing.

    Features:
    - Uses Shamir's Secret Sharing (SSS) for threshold key protection.
    - Supports XOR-based key splitting for lightweight implementations.
    - Includes verification mechanisms for secure reconstruction.
    """

    def __init__(self, threshold: int = 2, total_shares: int = 3):
        """
        Initialize MPC key sharing with a threshold & total shares.
        :param threshold: Minimum shares needed to reconstruct the secret.
        :param total_shares: Total key shares generated.
        """
        if threshold > total_shares:
            raise ValueError("Threshold cannot exceed total shares!")
        self.threshold = threshold
        self.total_shares = total_shares

    def generate_shamir_key_shares(self, secret: bytes) -> List[Tuple[int, bytes]]:
        """Generate secret shares using Shamir's Secret Sharing (SSS)."""
        return Shamir.split(self.threshold, self.total_shares, secret)

    def reconstruct_shamir_secret(self, shares: List[Tuple[int, bytes]]) -> bytes:
        """Reconstruct the original secret from Shamir key shares."""
        return Shamir.combine(shares)

    def generate_xor_key_shares(self, secret: bytes) -> List[bytes]:
        """Generate multiple key shares using XOR-based secret sharing."""
        shares = [secrets.token_bytes(len(secret)) for _ in range(self.total_shares - 1)]
        last_share = bytes(a ^ b for a, b in zip(secret, shares[0]))  # XOR-based secret sharing
        shares.append(last_share)
        return shares

    def reconstruct_xor_secret(self, shares: List[bytes]) -> bytes:
        """Reconstruct the original secret from XOR-based MPC shares."""
        secret = shares[0]
        for share in shares[1:]:
            secret = bytes(a ^ b for a, b in zip(secret, share))
        return secret

    def hash_secret(self, secret: bytes) -> str:
        """Generate a SHA-256 hash of the secret for integrity verification."""
        return hashlib.sha256(secret).hexdigest()

# 🔹 Example Usage
if __name__ == "__main__":
    mpc = MPCKeySharing(threshold=2, total_shares=3)

    original_secret = secrets.token_bytes(32)
    print(f"🔑 Original Secret: {original_secret.hex()}")

    # 🔹 Generate Shamir's Secret Shares
    shamir_shares = mpc.generate_shamir_key_shares(original_secret)
    print(f"🛡️ Shamir Secret Shares: {shamir_shares}")

    # 🔹 Reconstruct using threshold shares
    reconstructed_secret = mpc.reconstruct_shamir_secret(shamir_shares[:2])  # Using only threshold shares
    assert original_secret == reconstructed_secret, "❌ Shamir reconstruction failed!"
    print(f"✅ Reconstructed Secret: {reconstructed_secret.hex()}")

    # 🔹 Generate XOR-based Secret Shares
    xor_shares = mpc.generate_xor_key_shares(original_secret)
    print(f"🔄 XOR-Based Secret Shares: {xor_shares}")

    # 🔹 Reconstruct XOR secret
    xor_reconstructed_secret = mpc.reconstruct_xor_secret(xor_shares)
    assert original_secret == xor_reconstructed_secret, "❌ XOR reconstruction failed!"
    print(f"✅ XOR Reconstructed Secret: {xor_reconstructed_secret.hex()}")

    # 🔹 Verify Hash for Integrity Check
    print(f"🔏 Secret Hash: {mpc.hash_secret(original_secret)}")