import secrets
import hashlib
from typing import List, Tuple

def generate_mpc_key_shares(secret: bytes, num_shares: int) -> List[bytes]:
    """Generate multiple key shares for secure multi-party computation (MPC)."""
    shares = [secrets.token_bytes(len(secret)) for _ in range(num_shares - 1)]
    last_share = bytes(a ^ b for a, b in zip(secret, shares[0]))  # XOR-based secret sharing
    shares.append(last_share)
    return shares

def reconstruct_secret(shares: List[bytes]) -> bytes:
    """Reconstruct the original secret from MPC shares."""
    secret = shares[0]
    for share in shares[1:]:
        secret = bytes(a ^ b for a, b in zip(secret, share))
    return secret

if __name__ == "__main__":
    original_secret = secrets.token_bytes(32)
    print(f"Original Secret: {original_secret.hex()}")

    shares = generate_mpc_key_shares(original_secret, 3)
    reconstructed_secret = reconstruct_secret(shares)

    assert original_secret == reconstructed_secret, "Reconstructed secret does not match!"
    print(f"Reconstructed Secret: {reconstructed_secret.hex()}")
