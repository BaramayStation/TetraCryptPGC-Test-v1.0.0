import numpy as np
import hashlib

BLOCK_SIZE = 8  # Block size in bytes (64-bit blocks)
ROUNDS = 10     # Number of transformation rounds (tunable for security vs. performance)

def generate_key(passphrase: str) -> bytes:
    """Generate a 128-bit (16-byte) key from a passphrase deterministically using SHA-256."""
    # Hash the passphrase to create a fixed-length key.
    # Truncate to 16 bytes (128 bits) for use in this cipher.
    return hashlib.sha256(passphrase.encode('utf-8')).digest()[:16]

def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding to data to make its length a multiple of block_size."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def unpad_pkcs7(padded_data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 padding and return the original data."""
    if not padded_data:
        raise ValueError("Data is empty or corrupted (no padding found).")
    pad_len = padded_data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length.")
    # Check that all padding bytes have the correct value
    if padded_data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")
    return padded_data[:-pad_len]

def block_to_parts(block: bytes):
    """Split an 8-byte block into four 16-bit integer values (A, B, C, D)."""
    if len(block) != 8:
        raise ValueError("Block must be exactly 8 bytes.")
    # Combine each consecutive pair of bytes into a 16-bit number (big-endian)
    A = (block[0] << 8) | block[1]
    B = (block[2] << 8) | block[3]
    C = (block[4] << 8) | block[5]
    D = (block[6] << 8) | block[7]
    return A, B, C, D

def parts_to_block(A: int, B: int, C: int, D: int) -> bytes:
    """Combine four 16-bit integers (A, B, C, D) into an 8-byte block."""
    # Ensure values wrap around to 16-bit (in case of any overflow)
    A &= 0xFFFF; B &= 0xFFFF; C &= 0xFFFF; D &= 0xFFFF
    # Split each 16-bit int back into two bytes (big-endian order)
    return bytes([
        (A >> 8) & 0xFF, A & 0xFF,
        (B >> 8) & 0xFF, B & 0xFF,
        (C >> 8) & 0xFF, C & 0xFF,
        (D >> 8) & 0xFF, D & 0xFF
    ])

def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt a single 8-byte block using the tetrahedral cipher and a 128-bit key."""
    # Split block into four 16-bit parts
    A, B, C, D = block_to_parts(block)
    # Convert to Python ints for calculations
    A = int(A); B = int(B); C = int(C); D = int(D)
    # Prepare subkeys: derive 16-bit values from key bytes
    subkeys = [(key[i] << 8) | key[i+1] for i in range(0, len(key), 2)]
    # Perform ROUNDS iterations of the transformation
    for r in range(ROUNDS):
        # Use float64 for intermediate math to avoid any precision loss
        A_f = np.float64(A)
        B_f = np.float64(B)
        # Compute new value from A, B and the subkey (with a round-based offset for variation)
        k_val = (subkeys[r % len(subkeys)] + r) % 65536
        new_val = (A_f + B_f + k_val) % 65536  # add and wrap in 16-bit range
        new_val = int(new_val)                # convert back to int (exact for <= 16 bits)
        # Rotate the four values (A->B, B->C, C->D, new_val->D)
        A, B, C, D = B, C, D, new_val
    # Recombine into 8-byte encrypted block
    return parts_to_block(A, B, C, D)

def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt a single 8-byte block using the tetrahedral cipher and a 128-bit key."""
    # Split ciphertext block into four 16-bit parts
    A, B, C, D = block_to_parts(block)
    A = int(A); B = int(B); C = int(C); D = int(D)
    subkeys = [(key[i] << 8) | key[i+1] for i in range(0, len(key), 2)]
    # Reverse the ROUNDS transformations
    for r in reversed(range(ROUNDS)):
        # Compute the subkey and variation used in the corresponding encryption round
        k_val = (subkeys[r % len(subkeys)] + r) % 65536
        # Reverse rotation: identify original values before the last rotation in this round
        B_old = A   # A was B_old after encryption rotation
        C_old = B   # B was C_old
        D_old = C   # C was D_old
        new_val = D # D held the encrypted new_val (A_old + B_old + k_val)
        # Recover A_old by subtracting what was added in encryption: A_old = new_val - B_old - k_val (mod 2^16)
        A_old = (new_val - B_old - k_val) % 65536
        # Restore A, B, C, D to their values *before* this round
        A, B, C, D = A_old, B_old, C_old, D_old
    # Reassemble the original plaintext block
    return parts_to_block(A, B, C, D)

def encrypt_message(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt an arbitrary-length plaintext using the passphrase."""
    key = generate_key(passphrase)
    # Pad plaintext so its length is a multiple of 8 bytes
    padded = pad_pkcs7(plaintext, BLOCK_SIZE)
    ciphertext = b""
    # Encrypt each 8-byte block and append to ciphertext
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        ciphertext += encrypt_block(block, key)
    return ciphertext

def decrypt_message(ciphertext: bytes, passphrase: str) -> bytes:
    """Decrypt a ciphertext using the passphrase (the same one used for encryption)."""
    key = generate_key(passphrase)
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length is not a multiple of the block size (corrupted or incomplete).")
    padded_plaintext = b""
    # Decrypt each block and append to the plaintext buffer
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        padded_plaintext += decrypt_block(block, key)
    # Remove padding to retrieve the original plaintext
    return unpad_pkcs7(padded_plaintext, BLOCK_SIZE)

# Example usage demonstration
if __name__ == "__main__":
    sample_text = b"Hello, Tetra Encryption!"  # plaintext message as bytes
    passphrase = "mysecretpass"
    print("Original plaintext:", sample_text)
    encrypted = encrypt_message(sample_text, passphrase)
    print("Encrypted (hex):", encrypted.hex())
    decrypted = decrypt_message(encrypted, passphrase)
    print("Decrypted plaintext:", decrypted)
    print("Decryption successful?", decrypted == sample_text)
