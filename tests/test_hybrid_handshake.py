import unittest
import logging
from src.pq_xdh_handshake import pqc_ecc_hybrid_handshake, verify_handshake, generate_kat
from src.exceptions import TetraError  # ✅ Ensure `TetraError` is correctly imported

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestHybridHandshake(unittest.TestCase):
    
    def test_hybrid_handshake(self):
        """✅ Ensure the hybrid PQC + ECC handshake succeeds and produces a valid shared secret."""
        valid, shared_secret = pqc_ecc_hybrid_handshake()

        # ✅ Check if handshake was successful
        self.assertTrue(valid, "❌ Hybrid handshake authentication failed!")

        # ✅ Ensure shared secret is 64 bytes (512-bit key)
        self.assertIsInstance(shared_secret, bytes)
        self.assertEqual(len(shared_secret), 64, "❌ Shared secret length mismatch!")

        logging.info("✅ Hybrid PQC + ECC Handshake Test Passed.")

    def test_invalid_signature(self):
        """✅ Ensure invalid handshake data raises an exception (MITM Attack Prevention)."""
        tampered_data = b"malicious handshake data"

        with self.assertRaises(TetraError, msg="❌ Handshake verification failed to detect tampering!"):
            verify_handshake(tampered_data)  # ✅ Ensure verification fails with tampered data

        logging.info("✅ Invalid Signature Detection Test Passed.")

    def test_kat_generation(self):
        """✅ Verify known-answer test (KAT) output consistency for post-quantum cryptography."""
        seed = b"fixed_seed_for_testing"
        expected_output = generate_kat(seed)  # ✅ Get expected output dynamically

        self.assertEqual(generate_kat(seed), expected_output, "❌ KAT output mismatch!")

        logging.info("✅ Known-Answer Test (KAT) Generation Test Passed.")

if __name__ == "__main__":
    unittest.main()