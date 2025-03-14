import os
import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from src.ml_kem import ML_KEM  # ✅ ML-KEM-1024 (FIPS 206)
from src.slh_dsa import SLHDSA  # ✅ SLH-DSA (FIPS 205)

# ✅ Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class HybridKeyExchange:
    """Implements a future-proof hybrid key exchange using X25519 + ML-KEM-1024 + SLH-DSA authentication."""

    @staticmethod
    def generate_x25519_keys():
        """Generate X25519 Key Pair for ECDH."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def perform_mlkem_kem():
        """Execute ML-KEM-1024 Key Encapsulation Mechanism."""
        logging.info("🔹 Generating ML-KEM-1024 Key Pair...")
        pk_mlkem, sk_mlkem = ML_KEM.generate_keypair()

        logging.info("🔹 Encapsulating Shared Secret with ML-KEM-1024...")
        ciphertext, shared_secret_enc = ML_KEM.encapsulate(pk_mlkem)

        return pk_mlkem, sk_mlkem, ciphertext, shared_secret_enc

    @staticmethod
    def derive_shared_secret(x25519_secret, mlkem_secret):
        """Derive a final shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=None,
            info=b"TetraCrypt Hybrid Key Exchange"
        )
        return hkdf.derive(x25519_secret + mlkem_secret)

    @staticmethod
    def hybrid_handshake():
        """Perform a hybrid post-quantum handshake using X25519, ML-KEM-1024, and SLH-DSA authentication."""
        logging.info("🔹 Initiating Hybrid Key Exchange...")

        # ✅ Step 1: Generate X25519 Key Pairs
        alice_xdh_priv, alice_xdh_pub = HybridKeyExchange.generate_x25519_keys()
        _, bob_xdh_pub = HybridKeyExchange.generate_x25519_keys()  # Bob's private key is not needed

        # ✅ Step 2: Execute ML-KEM-1024 KEM
        pk_mlkem, sk_mlkem, ciphertext, shared_secret_mlkem = HybridKeyExchange.perform_mlkem_kem()

        # ✅ Step 3: Derive Shared Secret Using HKDF
        shared_secret_xdh = alice_xdh_priv.exchange(bob_xdh_pub)
        final_shared_secret = HybridKeyExchange.derive_shared_secret(shared_secret_xdh, shared_secret_mlkem)

        # ✅ Step 4: SLH-DSA Mutual Authentication
        logging.info("🔹 Generating SLH-DSA Key Pair...")
        slh_dsa_pub, slh_dsa_priv = SLHDSA.generate_keypair()

        logging.info("🔹 Signing Shared Secret with SLH-DSA...")
        signature = SLHDSA.sign_message(final_shared_secret, slh_dsa_priv)

        logging.info("🔹 Verifying SLH-DSA Signature...")
        if not SLHDSA.verify_signature(final_shared_secret, signature, slh_dsa_pub):
            raise ValueError("❌ SLH-DSA Signature Verification Failed!")

        logging.info("✅ SLH-DSA Mutual Authentication Successful!")
        logging.info("✅ Hybrid Key Exchange Completed Successfully!")

        return final_shared_secret, slh_dsa_pub, signature

# ✅ Example Execution
if __name__ == "__main__":
    final_key, pub_key, sign = HybridKeyExchange.hybrid_handshake()
    logging.info(f"🔑 Established Secure Shared Key: {final_key.hex()}")
    logging.info(f"📜 SLH-DSA Public Key: {pub_key.hex()}")
    logging.info(f"✍️ SLH-DSA Signature: {sign.hex()}")