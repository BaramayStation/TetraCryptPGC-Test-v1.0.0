import unittest
import logging
from unittest.mock import patch
from src.pq_ids import PQIDS  # ✅ Post-Quantum Intrusion Detection System (PQ-IDS)
from src.ml_kem import ML_KEM  # ✅ ML-KEM-1024 (FIPS 206)
from src.slh_dsa import SLHDSA  # ✅ SLH-DSA (FIPS 205)

# ✅ Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestPostQuantumIntrusionDetection(unittest.TestCase):
    """✅ Tests for the Post-Quantum Intrusion Detection System (PQ-IDS) against MITM attacks."""

    def setUp(self):
        """✅ Set up test data using ML-KEM-1024 and SLH-DSA for authentication."""
        self.peer = "peer_A"

        # ✅ Generate secure key pair using ML-KEM-1024
        self.public_key, self.secret_key = ML_KEM.generate_keypair()
        self.ciphertext, self.shared_secret = ML_KEM.encapsulate(self.public_key)

        # ✅ Generate SLH-DSA Signature
        self.slh_dsa_public, self.slh_dsa_private = SLHDSA.generate_keypair()
        self.signature = SLHDSA.sign_message(self.shared_secret, self.slh_dsa_private)

        # ✅ Tampered secret (Simulated MITM attack)
        self.tampered_secret = b"malicious_secret"
        self.tampered_signature = SLHDSA.sign_message(self.tampered_secret, self.slh_dsa_private)

    @patch("src.pq_ids.PQIDS.log_anomaly")  # ✅ Mock external logging function
    def test_post_quantum_mitm_detection(self, mock_log_anomaly):
        """✅ Ensure PQ-IDS detects post-quantum MITM attacks using ML-KEM & SLH-DSA."""

        # ✅ Test that original shared secret passes authentication
        result_original = PQIDS.detect_anomalies(self.shared_secret, self.signature, self.peer, self.slh_dsa_public)
        self.assertTrue(result_original, "❌ Original secret should pass verification!")

        # ✅ Test that altered shared secret is flagged as an anomaly
        result_tampered = PQIDS.detect_anomalies(self.tampered_secret, self.tampered_signature, self.peer, self.slh_dsa_public)
        self.assertFalse(result_tampered, "❌ Tampered secret should be flagged as MITM attack!")

        # ✅ Ensure that an anomaly is logged in the system
        mock_log_anomaly.assert_called_with(self.peer, self.tampered_secret, "SLH-DSA signature mismatch (MITM attack detected)")

        logging.info("✅ Post-Quantum MITM Attack Detection Test Passed.")

if __name__ == "__main__":
    unittest.main()