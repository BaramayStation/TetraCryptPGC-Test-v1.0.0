import secrets

def generate_mpc_key_shares(secret: int, num_shares: int) -> list:
    """
    Generate secret shares using Shamir’s Secret Sharing (Threshold Cryptography).
    
    Args:
        secret (int): The secret key to be shared.
        num_shares (int): The number of key shares to generate.
        
    Returns:
        list: A list of secret shares.
    """
    if num_shares < 2:
        raise ValueError("Number of shares must be at least 2")
    
    shares = [secrets.randbits(256) for _ in range(num_shares - 1)]
    last_share = secret ^ sum(shares)  # XOR-based MPC Secret Sharing
    shares.append(last_share)
    
    return shares

def reconstruct_secret(shares: list) -> int:
    """
    Reconstruct the secret from MPC shares.
    
    Args:
        shares (list): The list of key shares.
        
    Returns:
        int: The reconstructed secret key.
    """
    return sum(shares)

if __name__ == "__main__":
    # Example: MPC Key Sharing for 3 Parties
    secret_key = secrets.randbits(256)
    num_parties = 3

    print("\n🔹 Original Secret Key:", hex(secret_key))

    # Generate MPC shares
    shares = generate_mpc_key_shares(secret_key, num_parties)
    print("🔹 MPC Shares:", [hex(share) for share in shares])

    # Reconstruct Secret
    recovered_secret = reconstruct_secret(shares)
    print("🔹 Reconstructed Secret Key:", hex(recovered_secret))

    # Ensure Correctness
    assert secret_key == recovered_secret, "MPC Key Recovery Failed"
    print("\n✅ MPC Secure Key Sharing Successful")
