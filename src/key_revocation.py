import os
import json

REVOCATION_LIST = "/app/keys/revoked.json"

def load_revocation_list():
    """Load the revoked key list from disk."""
    if not os.path.exists(REVOCATION_LIST):
        return []
    with open(REVOCATION_LIST, "r") as f:
        return json.load(f)

def revoke_key(key_id: str):
    """Revoke a key and add it to the revocation list."""
    revoked_keys = load_revocation_list()
    revoked_keys.append({"key_id": key_id, "revoked_at": time.time()})

    with open(REVOCATION_LIST, "w") as f:
        json.dump(revoked_keys, f, indent=4)

    print(f"Key {key_id} revoked successfully.")
