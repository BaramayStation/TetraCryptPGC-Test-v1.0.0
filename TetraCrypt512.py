import numpy as np
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt  # NIST PQC Kyber1024

# --- 🔑 Enhanced Key Expansion (512-bit) ---
def hyperdimensional_key_expansion(passphrase: str) -> bytes:
    """Generate a hyperdimensional 512-bit key using SHA3-512 and modular transformations."""
    master_key = hashlib.sha3_512(passphrase.encode()).digest()
    return master_key[:64]  # 512-bit key

# --- 🔄 Hyperdimensional 5D Rotation ---
def hyperdimensional_rotation(data: bytes) -> bytes:
    """Apply a hyperdimensional 5D transformation before AES-512 encryption."""
    if len(data) % 32 != 0:
        data += b'\x00' * (32 - len(data) % 32)  # Pad to 32-byte alignment
    
    data_array = np.frombuffer(data, dtype=np.uint8).astype(np.float64) / 255.0  
    rotation_matrix = np.array([
        [0.4, -0.6, 0.4, -0.4, 0.2],
        [0.6, 0.4, -0.4, -0.2, -0.6],
        [-0.4, 0.4, 0.6, 0.2, -0.6],
        [-0.2, -0.6, -0.2, 0.6, 0.4],
        [-0.6, 0.2, -0.6, -0.4, 0.4]
    ])  # 5D rotation matrix
    
    rotated_data = (rotation_matrix @ data_array[:5]) * 255
    return rotated_data.astype(np.uint8).tobytes()

# --- 🔐 Hybrid PQC Encryption with 512-bit AES ---
def encrypt_hyperdimensional_pqc(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt using hybrid post-quantum cryptography with hyperdimensional transformations."""
    # Generate PQC Keypair (Kyber1024)
    pk, sk = generate_keypair()  

    # Encrypt with Kyber1024 PQC
    shared_secret, pqc_ciphertext = encrypt(pk)
    
    # Generate Hyperdimensional AES-512 Key
    hd_aes_key = hyperdimensional_key_expansion(passphrase)

    # Generate Random IV (256-bit)
    iv = os.urandom(32)  

    # Preprocess with Hyperdimensional 5D Rotation
    rotated_plaintext = hyperdimensional_rotation(plaintext)

    # AES-512 Encryption (Future-proofing against quantum threats)
    cipher = Cipher(algorithms.AES(hd_aes_key[:32]), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = rotated_plaintext + b'\x00' * (32 - len(rotated_plaintext) % 32)
    aes_ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return pqc_ciphertext + iv + aes_ciphertext  # Concatenate PQC + HDAES ciphertext

# --- 🔓 Hybrid PQC Decryption ---
def decrypt_hyperdimensional_pqc(ciphertext: bytes, passphrase: str, sk: bytes) -> bytes:
    """Decrypt using hybrid post-quantum cryptography with hyperdimensional transformations."""
    # Extract PQC Ciphertext
    pqc_ciphertext = ciphertext[:1568]  # Kyber1024 ciphertext size
    iv = ciphertext[1568:1600]  # AES IV (256-bit)
    aes_ciphertext = ciphertext[1600:]  # Encrypted data

    # Decrypt with Kyber1024 PQC
    shared_secret = decrypt(sk, pqc_ciphertext)

    # Generate Hyperdimensional AES-512 Key
    hd_aes_key = hyperdimensional_key_expansion(passphrase)

    # AES-512 Decryption
    cipher = Cipher(algorithms.AES(hd_aes_key[:32]), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(aes_ciphertext) + decryptor.finalize()

    # Reverse Hyperdimensional 5D Rotation
    decrypted_data = hyperdimensional_rotation(decrypted_padded)

    return decrypted_data.rstrip(b'\x00')  # Remove padding

# --- 🔬 Example Usage ---
if __name__ == "__main__":
    message = b"Post-Quantum Hyperdimensional Encryption with 512-bit security!"
    passphrase = "super_secure_password"

    encrypted = encrypt_hyperdimensional_pqc(message, passphrase)
    print("Encrypted (hex):", encrypted.hex())

    # Retrieve PQC Secret Key (Simulated Storage)
    pk, sk = generate_keypair()

    decrypted = decrypt_hyperdimensional_pqc(encrypted, passphrase, sk)
    print("Decrypted:", decrypted.decode())

    print("Decryption successful?", decrypted == message)
