from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ecc_keypair(curve="X25519"):
    """Generate an ECC key pair (X25519 or P-384)."""
    if curve == "X25519":
        private_key = x25519.X25519PrivateKey.generate()
    elif curve == "P-384":
        private_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError("Unsupported curve. Choose 'X25519' or 'P-384'.")

    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    """Convert a public key to bytes for transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key):
    """Convert a private key to bytes for secure storage."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_public_key(public_key_bytes):
    """Convert bytes back to a public key object."""
    return serialization.load_pem_public_key(public_key_bytes)

def deserialize_private_key(private_key_bytes):
    """Convert bytes back to a private key object."""
    return serialization.load_pem_private_key(private_key_bytes, password=None)

def derive_ecc_shared_secret(private_key, peer_public_key):
    """Derive a shared secret using ECC Diffie-Hellman."""
    try:
        if isinstance(peer_public_key, bytes):
            peer_public_key = deserialize_public_key(peer_public_key)

        shared_secret = private_key.exchange(peer_public_key)

        # Normalize the shared secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit shared secret
            salt=None,
            info=b"TetraHybridPQ",
        )
        return hkdf.derive(shared_secret)

    except Exception as e:
        raise ValueError(f"Failed to derive shared secret: {e}")

# Example Usage
if __name__ == "__main__":
    # Alice generates her key pair
    alice_private, alice_public = generate_ecc_keypair("X25519")

    # Bob generates his key pair
    bob_private, bob_public = generate_ecc_keypair("X25519")

    # Alice and Bob exchange public keys (simulate network transmission)
    alice_public_bytes = serialize_public_key(alice_public)
    bob_public_bytes = serialize_public_key(bob_public)

    # Deserialize received keys
    bob_public_received = deserialize_public_key(bob_public_bytes)
    alice_public_received = deserialize_public_key(alice_public_bytes)

    # Compute shared secret
    shared_secret_alice = derive_ecc_shared_secret(alice_private, bob_public_received)
    shared_secret_bob = derive_ecc_shared_secret(bob_private, alice_public_received)

    # Verify both parties derived the same secret
    assert shared_secret_alice == shared_secret_bob, "Shared secrets do not match!"

    print(f"Shared Secret: {shared_secret_alice.hex()}")
    print("ECC Key Exchange Successful ✅")
