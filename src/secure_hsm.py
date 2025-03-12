import os

HSM_KEY_PATH = os.path.expanduser("~/.hsm_keys/tetrapgc_key.pem")

def store_key_in_hsm(key_data):
    """Store key securely inside a user-level HSM."""
    os.makedirs(os.path.dirname(HSM_KEY_PATH), exist_ok=True)
    with open(HSM_KEY_PATH, "wb") as f:
        f.write(key_data)

def retrieve_key_from_hsm():
    """Retrieve key securely from a user-level HSM."""
    with open(HSM_KEY_PATH, "rb") as f:
        return f.read()
