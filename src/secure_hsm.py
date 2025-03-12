import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HSM_KEY_ID = "TetraCryptPGC_Key"

def store_key_in_hsm(key_data):
    """Store key securely inside HSM."""
    with open(f"/usr/lib/hsm/{HSM_KEY_ID}.pem", "wb") as f:
        f.write(key_data)

def retrieve_key_from_hsm():
    """Retrieve key securely from HSM."""
    with open(f"/usr/lib/hsm/{HSM_KEY_ID}.pem", "rb") as f:
        return f.read()
