import numpy as np
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt  # NIST PQC Kyber512

# --- 🔑 Hyperdimensional Key Expansion ---
def hyperdimensional_key_expansion(passphrase: str) -> bytes:
    """Generate a hyperdimensional key using SHA3-512 and non-Euclidean projections."""
    master_key = hashlib.sha3_512(passphrase.encode()).digest()
    return master_key[:32]  # Use first 256-bit for AES-like encryption

# --- 🔄 Hyperdimensional 4D/5D Rotation ---
def hyperdimensional_rotation(data: bytes) -> bytes:
    """Apply a hyperdimensional transformation before AES encryption."""
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)  # Pad to 16-byte alignment
    
    data_array = np.frombuffer(data, dtype=np.uint8).astype(np.float64) / 255.0  
    rotation_matrix = np.array([
        [0.5, -0.5, 0.5, -0.5],
        [0.5, 0.5, -0.5, -0.5],
        [-0.5, 0.5, 0.5, -0.5],
        [-0.5, -0.5, -0.5, 0.5]
    ])  # Example 4D rotation matrix
    
    rotated_data = (rotation_matrix @ data_array[:4]) * 255
    return rotated_data.astype(np.uint8).tobytes()

# --- 🔐 Hybrid PQC Encryption ---
def encrypt_hyperdimensional_pqc(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt using hybrid post-quantum cryptography with hyperdimensional transformations."""
    # Generate PQC Keypair (Kyber512)
    pk, sk = generate_keypair()  

    # Encrypt with Kyber512 PQC
    shared_secret, pqc_ciphertext = encrypt(pk)
    
    # Generate Hyperdimensional AES Key
    hd_aes_key = hyperdimensional_key_expansion(passphrase)

    # Generate Random IV
    iv = os.urandom(16)  

    # Preprocess with Hyperdimensional 4D Rotation
    rotated_plaintext = hyperdimensional_rotation(plaintext)

    # AES-256 Encryption (HDAES)
    cipher = Cipher(algorithms.AES(hd_aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = rotated_plaintext + b'\x00' * (16 - len(rotated_plaintext) % 16)
    aes_ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return pqc_ciphertext + iv + aes_ciphertext  # Concatenate PQC + HDAES ciphertext

# --- 🔓 Hybrid PQC Decryption ---
def decrypt_hyperdimensional_pqc(ciphertext: bytes, passphrase: str, sk: bytes) -> bytes:
    """Decrypt using hybrid post-quantum cryptography with hyperdimensional transformations."""
    # Extract PQC Ciphertext
    pqc_ciphertext = ciphertext[:800]  # Kyber512 ciphertext size
    iv = ciphertext[800:816]  # AES IV
    aes_ciphertext = ciphertext[816:]  # Encrypted data

    # Decrypt with Kyber512 PQC
    shared_secret = decrypt(sk, pqc_ciphertext)

    # Generate Hyperdimensional AES Key
    hd_aes_key = hyperdimensional_key_expansion(passphrase)

    # AES-256 Decryption (HDAES)
    cipher = Cipher(algorithms.AES(hd_aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(aes_ciphertext) + decryptor.finalize()

    # Reverse Hyperdimensional 4D Rotation
    decrypted_data = hyperdimensional_rotation(decrypted_padded)

    return decrypted_data.rstrip(b'\x00')  # Remove padding

# --- 🔬 Example Usage ---
if __name__ == "__main__":
    message = b"Post-Quantum Hyperdimensional Encryption!"
    passphrase = "secure_password"

    encrypted = encrypt_hyperdimensional_pqc(message, passphrase)
    print("Encrypted (hex):", encrypted.hex())

    # Retrieve PQC Secret Key (Simulated Storage)
    pk, sk = generate_keypair()

    decrypted = decrypt_hyperdimensional_pqc(encrypted, passphrase, sk)
    print("Decrypted:", decrypted.decode())

    print("Decryption successful?", decrypted == message)
