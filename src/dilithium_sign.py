from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify

def dilithium_keygen():
    """Generate a Dilithium key pair."""
    return generate_keypair()

def dilithium_sign(message, private_key):
    """Sign a message using Dilithium-3."""
    return sign(message, private_key)

def dilithium_verify(message, signature, public_key):
    """Verify a Dilithium-3 signature."""
    return verify(signature, message, public_key)
