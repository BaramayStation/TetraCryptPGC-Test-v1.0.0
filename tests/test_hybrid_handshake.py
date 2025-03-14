import unittest
import logging
from src.hybrid_key_exchange import HybridKeyExchange
from src.slh_dsa import SLHDSA
from src.exceptions import TetraError  # ✅ Custom Exception Handling

# ✅ Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestHybridHandshake(unittest.TestCase):
    
    def test_hybrid_handshake(self):
        """✅ Ensure the hybrid ML-KEM-1024 + X25519 handshake succeeds and produces a valid shared secret."""
        shared_secret, slh_dsa_pub, signature = HybridKeyExchange.hybrid_handshake()

        # ✅ Ensure the shared secret is valid
        self.assertIsInstance(shared_secret, bytes)
        self.assertEqual(len(shared_secret), 64, "❌ Shared secret length mismatch!")  # ✅ Should be 512-bit

        # ✅ Validate SLH-DSA signature
        valid_signature = SLHDSA.verify_signature(shared_secret, signature, slh_dsa_pub)
        self.assertTrue(valid_signature, "❌ SLH-DSA Signature Verification Failed!")

        logging.info("✅ Hybrid ML-KEM-1024 + X25519 Handshake Test Passed.")

    def test_invalid_signature(self):
        """✅ Ensure invalid handshake data raises an exception (MITM Attack Prevention)."""
        shared_secret, slh_dsa_pub, signature = HybridKeyExchange.hybrid_handshake()
        
        tampered_signature = b"tampered_signature_data"

        with self.assertRaises(TetraError, msg="❌ Failed to detect signature tampering!"):
            SLHDSA.verify_signature(shared_secret, tampered_signature, slh_dsa_pub)

        logging.info("✅ Invalid Signature Detection Test Passed.")

if __name__ == "__main__":
    unittest.main()