import os
import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from src.ml_kem import ML_KEM  # ✅ Secure FIPS 206 ML-KEM-1024

# ✅ Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class HybridKeyExchange:
    """Implements a hybrid post-quantum key exchange using ML-KEM-1024 + X25519."""

    @staticmethod
    def generate_x25519_keys():
        """Generate an X25519 key pair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def perform_ml_kem_kem():
        """Perform ML-KEM-1024 Key Encapsulation Mechanism (KEM)."""
        logging.info("🔹 Generating ML-KEM-1024 Key Pair...")
        pk_ml_kem, sk_ml_kem = ML_KEM.generate_keypair()

        logging.info("🔹 Encapsulating Shared Secret with ML-KEM-1024...")
        ciphertext, shared_secret_ml_kem = ML_KEM.encapsulate(pk_ml_kem)

        return pk_ml_kem, sk_ml_kem, shared_secret_ml_kem

    @staticmethod
    def hybrid_key_exchange():
        """Perform a hybrid post-quantum handshake using ML-KEM-1024 + X25519."""
        logging.info("🔹 Initiating Hybrid ML-KEM-1024 + X25519 Key Exchange...")

        # Step 1: Generate X25519 Key Pairs
        x25519_priv, x25519_pub = HybridKeyExchange.generate_x25519_keys()

        # Step 2: Execute ML-KEM-1024 KEM
        pk_ml_kem, sk_ml_kem, shared_secret_ml_kem = HybridKeyExchange.perform_ml_kem_kem()

        # Step 3: Derive Shared Secret Using X25519
        shared_secret_x25519 = x25519_priv.exchange(x25519_pub)

        # Step 4: Derive Final Hybrid Shared Secret Using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=None,
            info=b"TetraCrypt Hybrid Key Exchange"
        )
        final_shared_secret = hkdf.derive(shared_secret_x25519 + shared_secret_ml_kem)

        logging.info("✅ Hybrid Key Exchange Successful!")
        return final_shared_secret, pk_ml_kem, x25519_pub

# ✅ Example Execution
if __name__ == "__main__":
    hybrid_key = HybridKeyExchange.hybrid_key_exchange()
    logging.info(f"🔑 Established Secure Hybrid Key: {hybrid_key[0].hex()}")
