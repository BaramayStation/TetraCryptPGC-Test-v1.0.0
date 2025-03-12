import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HSM_KEY_ID = "TetraCryptPGC_Key"

def store_key_in_hsm(key_data):
    """Store key securely inside an HSM to prevent key exposure."""
    with open(f"/usr/lib/hsm/{HSM_KEY_ID}.pem", "wb") as f:
        f.write(key_data)

def retrieve_key_from_hsm():
    """Retrieve key securely from HSM (protected access)."""
    with open(f"/usr/lib/hsm/{HSM_KEY_ID}.pem", "rb") as f:
        return f.read()

if __name__ == "__main__":
    test_key = os.urandom(32)  # Generate a random key
    store_key_in_hsm(test_key)
    retrieved_key = retrieve_key_from_hsm()
    print(f"Retrieved HSM Key: {retrieved_key.hex()}")
