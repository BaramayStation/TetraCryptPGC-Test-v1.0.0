Tetrahedral Encryption System 🔐
A lightweight, custom encryption algorithm using tetrahedral transformations and a 128-bit key derived from a passphrase.

Overview
The Tetrahedral Encryption System is a 64-bit block cipher that encrypts and decrypts messages using a geometrically inspired transformation based on tetrahedral rotations. It supports arbitrary message lengths, deterministic key derivation, and secure PKCS#7 padding.

This project is intended for educational and experimental purposes. It is not a standard cryptographic algorithm, so it should not be used for sensitive applications.

Features
✅ 128-bit key generation from a passphrase (SHA-256 derived)
✅ 64-bit block encryption with a configurable number of rounds (default: 10)
✅ PKCS#7 padding for handling arbitrary message lengths
✅ Reversible transformation ensures lossless decryption
✅ Self-contained, no external dependencies (requires only numpy)
✅ Lightweight and easy to understand for cryptography learners

Installation
Clone the repository:

git clone https://github.com/Abraxas618/TetraCrypt/blob/main/tetracrypt.py
cd tetrahedral-encryption
Install dependencies (only numpy is required):

pip install numpy
Usage
Encryption & Decryption Example


from tetra_cipher import encrypt_message, decrypt_message

plaintext = b"Hello, Tetra Encryption!"
passphrase = "mysecretpass"

# Encrypt the message
encrypted = encrypt_message(plaintext, passphrase)
print("Encrypted (hex):", encrypted.hex())

# Decrypt the message
decrypted = decrypt_message(encrypted, passphrase)
print("Decrypted:", decrypted.decode())

📌 Important: The same passphrase must be used for both encryption and decryption.

How It Works
Passphrase-based Key Derivation: A 128-bit encryption key is derived from the passphrase using SHA-256.
Block Transformation: Each 8-byte block is split into four 16-bit parts, then undergoes 10 rounds of encryption using key-dependent tetrahedral transformations.
PKCS#7 Padding: Ensures the message length is a multiple of 8 bytes.
Decryption Reversibility: The same steps are applied in reverse order to perfectly reconstruct the original plaintext.
Security Considerations
🔒 This encryption system is not a standard cryptographic cipher like AES or ChaCha20.
🔍 It is suitable for experimental and educational use but not for securing sensitive data.

For real-world security, consider AES-256 (Advanced Encryption Standard) or other well-audited encryption libraries like PyCryptodome.

License
📜 MIT License – Feel free to modify and share!

Contributions
We welcome improvements and optimizations! Feel free to submit pull requests or report issues.

Author
👨‍💻 Created by Abraxas618
🔗 GitHub: https://github.com/Abraxas618

🎯 Ready to encrypt? Start experimenting today! 🚀 
