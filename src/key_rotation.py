import os
import time
from src.kyber_kem import kyber_keygen
from src.falcon_sign import falcon_keygen

ROTATION_INTERVAL = 30 * 24 * 60 * 60  # Rotate every 30 days
KEY_STORAGE = "/app/keys"

def rotate_keys():
    """Generate new Kyber and Falcon key pairs at regular intervals."""
    if not os.path.exists(KEY_STORAGE):
        os.makedirs(KEY_STORAGE)

    new_kyber_pk, new_kyber_sk = kyber_keygen()
    new_falcon_pk, new_falcon_sk = falcon_keygen()

    timestamp = int(time.time())
    with open(f"{KEY_STORAGE}/kyber_{timestamp}.pub", "wb") as f:
        f.write(new_kyber_pk)
    with open(f"{KEY_STORAGE}/kyber_{timestamp}.key", "wb") as f:
        f.write(new_kyber_sk)
    with open(f"{KEY_STORAGE}/falcon_{timestamp}.pub", "wb") as f:
        f.write(new_falcon_pk)
    with open(f"{KEY_STORAGE}/falcon_{timestamp}.key", "wb") as f:
        f.write(new_falcon_sk)

    print(f"Keys rotated at {time.ctime(timestamp)}")

if __name__ == "__main__":
    rotate_keys()
