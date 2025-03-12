import os

def store_key_in_trustzone(key):
    """Store key inside TrustZone using OP-TEE."""
    with open("/secure_storage/trustzone_key.bin", "wb") as f:
        f.write(key)

def retrieve_key_from_trustzone():
    """Retrieve key from TrustZone Secure Storage."""
    with open("/secure_storage/trustzone_key.bin", "rb") as f:
        return f.read()
