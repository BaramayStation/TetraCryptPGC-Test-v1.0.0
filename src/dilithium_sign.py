from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify

def dilithium_keygen():
    """Generate a secure Dilithium-3 key pair with error handling."""
    try:
        public_key, private_key = generate_keypair()
        return public_key, private_key
    except Exception as e:
        raise RuntimeError(f"Dilithium Key Generation Failed: {e}")

def dilithium_sign(message, private_key):
    """Sign a message securely using Dilithium-3."""
    if not isinstance(message, bytes):
        message = message.encode("utf-8")  # Ensure message is in byte format
    try:
        return sign(message, private_key)
    except Exception as e:
        raise RuntimeError(f"Dilithium Signing Failed: {e}")

def dilithium_verify(message, signature, public_key):
    """Verify a Dilithium-3 signature with explicit boolean return."""
    if not isinstance(message, bytes):
        message = message.encode("utf-8")  # Convert to bytes if needed
    try:
        verify(signature, message, public_key)
        return True  # Signature is valid
    except Exception:
        return False  # Signature verification failed

# Example Usage
if __name__ == "__main__":
    # Generate Key Pair
    pub_key, priv_key = dilithium_keygen()

    # Example message
    message = "This is a secure post-quantum message."

    # Sign the message
    signature = dilithium_sign(message, priv_key)
    print(f"Signature: {signature.hex()}")

    # Verify the signature
    is_valid = dilithium_verify(message, signature, pub_key)
    print(f"Signature Verification: {'Valid' if is_valid else 'Invalid'}")
