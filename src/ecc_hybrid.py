from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization

def generate_ecc_keypair(curve="X25519"):
    """Generate an ECC key pair (X25519 or P-384)."""
    if curve == "X25519":
        private_key = x25519.X25519PrivateKey.generate()
    elif curve == "P-384":
        private_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError("Unsupported curve. Choose 'X25519' or 'P-384'.")

    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Convert a public key to bytes for transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_ecc_shared_secret(private_key, peer_public_key):
    """Derive a shared secret using ECC Diffie-Hellman."""
    return private_key.exchange(peer_public_key)
