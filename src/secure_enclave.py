import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from google.cloud import kms

class SecureEnclave:
    def __init__(self, project_id, location, key_ring, key_name):
        """Initialize Google Cloud KMS for secure key storage."""
        self.client = kms.KeyManagementServiceClient()
        self.key_path = self.client.crypto_key_path(project_id, location, key_ring, key_name)

    def encrypt_key(self, key):
        """Encrypt a key using Google Cloud KMS."""
        ciphertext = self.client.encrypt(self.key_path, plaintext=key).ciphertext
        return ciphertext

    def decrypt_key(self, ciphertext):
        """Decrypt a key using Google Cloud KMS."""
        plaintext = self.client.decrypt(self.key_path, ciphertext=ciphertext).plaintext
        return plaintext
