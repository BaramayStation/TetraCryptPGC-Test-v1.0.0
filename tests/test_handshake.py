import unittest
import logging
from src.hybrid_key_exchange import HybridKeyExchange
from src.ml_kem import ML_KEM  # ✅ ML-KEM-1024 (FIPS 206)
from src.slh_dsa import SLHDSA  # ✅ SLH-DSA (FIPS 205)
from src.exceptions import TetraError  # ✅ Custom Exception Handling

# ✅ Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestHybridKeyExchange(unittest.TestCase):

    def test_ml_kem_key_generation(self):
        """✅ Test ML-KEM-1024 key pair generation."""
        pk, sk = ML_KEM.generate_keypair()

        # ✅ Ensure correct key sizes for ML-KEM-1024
        self.assertEqual(len(pk), 1568, "❌ ML-KEM-1024 public key size mismatch")
        self.assertEqual(len(sk), 3168, "❌ ML-KEM-1024 secret key size mismatch")
        logging.info("✅ ML-KEM-1024 Key Generation Test Passed.")

    def test_ml_kem_encapsulation_decapsulation(self):
        """✅ Test ML-KEM-1024 encapsulation and decapsulation."""
        pk, sk = ML_KEM.generate_keypair()
        ciphertext, shared_secret_enc = ML_KEM.encapsulate(pk)
        shared_secret_dec = ML_KEM.decapsulate(ciphertext, sk)

        self.assertEqual(shared_secret_enc, shared_secret_dec, "❌ ML-KEM shared secrets do not match")
        logging.info("✅ ML-KEM-1024 Encapsulation & Decapsulation Test Passed.")

    def test_slh_dsa_signature_verification(self):
        """✅ Test SLH-DSA signing and verification."""
        pk, sk = SLHDSA.generate_keypair()
        message = b"Post-Quantum Test Message"
        signature = SLHDSA.sign_message(message, sk)

        self.assertTrue(SLHDSA.verify_signature(message, signature, pk), "❌ SLH-DSA signature verification failed")
        logging.info("✅ SLH-DSA Signature Verification Test Passed.")

    def test_full_hybrid_handshake(self):
        """✅ Test the full hybrid post-quantum key exchange (ML-KEM-1024 + SLH-DSA)."""
        shared_secret, slh_dsa_pub, signature = HybridKeyExchange.hybrid_handshake()

        # ✅ Ensure the shared secret is valid
        self.assertIsInstance(shared_secret, bytes)
        self.assertEqual(len(shared_secret), 64, "❌ Hybrid shared secret length mismatch!")  # ✅ 512-bit

        # ✅ Validate SLH-DSA signature
        valid_signature = SLHDSA.verify_signature(shared_secret, signature, slh_dsa_pub)
        self.assertTrue(valid_signature, "❌ SLH-DSA Signature Verification Failed!")

        logging.info("✅ Full Hybrid Key Exchange Test Passed.")

if __name__ == "__main__":
    unittest.main()