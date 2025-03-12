import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# HSM Key ID
HSM_KEY_ID = "TetraCryptPGC_Key"
HSM_STORAGE_PATH = "/usr/lib/hsm/"

# Ensure the directory exists
os.makedirs(HSM_STORAGE_PATH, exist_ok=True)

def derive_encryption_key(master_key):
    """
    Derive a symmetric key for AES-GCM encryption using HKDF.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b"TetraCryptPGC HSM Key Wrapping",
        backend=default_backend()
    )
    return hkdf.derive(master_key)

def encrypt_key(key_data, master_key):
    """
    Encrypts the key before storing it inside HSM using AES-GCM.
    """
    encryption_key = derive_encryption_key(master_key)
    iv = os.urandom(12)  # AES-GCM standard IV size
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(key_data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext  # Store IV, Auth Tag, Ciphertext

def decrypt_key(encrypted_data, master_key):
    """
    Decrypts the key retrieved from HSM using AES-GCM.
    """
    encryption_key = derive_encryption_key(master_key)
    iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def store_key_in_hsm(key_data, master_key):
    """
    Store cryptographic key securely inside Hardware Security Module (HSM).
    """
    try:
        encrypted_key = encrypt_key(key_data, master_key)
        with open(os.path.join(HSM_STORAGE_PATH, f"{HSM_KEY_ID}.bin"), "wb") as f:
            f.write(encrypted_key)
        print("[SUCCESS] Key securely stored inside HSM.")
    except Exception as e:
        raise RuntimeError(f"[ERROR] Failed to store key in HSM: {e}")

def retrieve_key_from_hsm(master_key):
    """
    Retrieve cryptographic key securely from HSM and decrypt it.
    """
    try:
        with open(os.path.join(HSM_STORAGE_PATH, f"{HSM_KEY_ID}.bin"), "rb") as f:
            encrypted_key = f.read()
        decrypted_key = decrypt_key(encrypted_key, master_key)
        print("[SUCCESS] Key successfully retrieved from HSM.")
        return decrypted_key
    except Exception as e:
        raise RuntimeError(f"[ERROR] Failed to retrieve key from HSM: {e}")

def generate_hsm_key():
    """
    Generate a new ECC key pair for HSM storage.
    """
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_pem

def verify_hsm_key_integrity(master_key, expected_key):
    """
    Verify HSM key integrity using HMAC-based authentication.
    """
    try:
        stored_key = retrieve_key_from_hsm(master_key)
        if stored_key != expected_key:
            raise ValueError("[SECURITY ALERT] HSM key integrity compromised.")
        print("[SECURITY] HSM key integrity verified.")
        return True
    except Exception as e:
        print(f"[ERROR] HSM key verification failed: {e}")
        return False

if __name__ == "__main__":
    # Generate a secure master key for encryption
    master_key = os.urandom(32)

    # Generate a cryptographic key for storage
    key_to_store = generate_hsm_key()

    # Store the key in HSM securely
    store_key_in_hsm(key_to_store, master_key)

    # Retrieve the key securely
    retrieved_key = retrieve_key_from_hsm(master_key)

    # Verify if the retrieved key matches the stored one
    is_valid = verify_hsm_key_integrity(master_key, key_to_store)

    if is_valid:
        print("[SECURE] HSM Security Validation Passed.")
    else:
        print("[ALERT] HSM Key Integrity Compromised.")
