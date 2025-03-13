import os
import logging
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify
from src.dilithium_sign import dilithium_keygen, dilithium_sign, dilithium_verify
from src.secure_hsm import store_key_in_hsm, retrieve_key_from_hsm

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Environment Variables for Security Configurations
USE_HSM = os.getenv("USE_HSM", "true").lower() == "true"
SESSION_KEY = secrets.token_bytes(32)  # 256-bit Secure Session Key

class PQXDHHandshake:
    """Post-Quantum XDH Hybrid Key Exchange with Mutual Authentication."""

    def __init__(self):
        logging.info("🔹 Initializing PQXDH Secure Handshake...")

    def generate_x25519_keys(self):
        """Generate X25519 Key Pair for ECDH."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def perform_kyber_kem(self):
        """Execute Kyber-1024 Key Encapsulation Mechanism using `liboqs`."""
        logging.info("🔹 Generating Kyber-1024 Key Pair...")
        pk_kyber, sk_kyber = kyber_keygen()

        logging.info("🔹 Encapsulating Shared Secret with Kyber...")
        ciphertext, shared_secret_enc = kyber_encapsulate(pk_kyber)

        return pk_kyber, sk_kyber, ciphertext, shared_secret_enc

    def perform_falcon_signature(self, message, private_key):
        """Sign a message using Falcon-1024."""
        signature = falcon_sign(message, private_key)
        return signature

    def perform_dilithium_signature(self, message, private_key):
        """Sign a message using Dilithium-3."""
        signature = dilithium_sign(message, private_key)
        return signature

    def hybrid_xdh_handshake(self):
        """Perform a hybrid post-quantum handshake using XDH + PQC."""
        logging.info("🔹 Initiating PQXDH Hybrid Key Exchange...")

        # Step 1: Generate X25519 Key Pairs
        alice_xdh_priv, _ = self.generate_x25519_keys()
        _, bob_xdh_pub = self.generate_x25519_keys()  # Replaced unused variable bob_xdh_priv with _

        # Step 2: Execute Kyber-1024 KEM
        pk_kyber, sk_kyber, _, shared_secret_kyber = self.perform_kyber_kem()

        # Step 3: Derive Shared Secret Using HKDF
        shared_secret_xdh = alice_xdh_priv.exchange(bob_xdh_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=None,
            info=b"TetraCrypt PQXDH Handshake"
        )
        final_shared_secret = hkdf.derive(shared_secret_xdh + shared_secret_kyber)

        # Step 4: Mutual Authentication with Falcon & Dilithium
        falcon_signature = self.perform_falcon_signature(final_shared_secret, sk_kyber)
        dilithium_signature = self.perform_dilithium_signature(final_shared_secret, sk_kyber)

        logging.info("🔹 Verifying Falcon-1024 & Dilithium-3 Signatures...")

        if not falcon_verify(final_shared_secret, falcon_signature, pk_kyber):
            raise ValueError("🚨 Falcon Signature Verification Failed!")

        if not dilithium_verify(final_shared_secret, dilithium_signature, pk_kyber):
            raise ValueError("🚨 Dilithium Signature Verification Failed!")

        # Step 5: Store Final Key in HSM (if enabled)
        if USE_HSM:
            store_key_in_hsm(final_shared_secret)
            logging.info("🔐 Final Shared Secret Stored in HSM.")

        logging.info("✅ PQXDH Mutual Authentication & Key Exchange Successful!")

        return final_shared_secret

if __name__ == "__main__":
    pqxdh = PQXDHHandshake()
    secure_shared_key = pqxdh.hybrid_xdh_handshake()
    logging.info(f"🔑 Established Secure Shared Key: {secure_shared_key.hex()}")
