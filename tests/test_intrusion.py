import unittest
import logging
from unittest.mock import patch
from src.intrusion_detection import IDS  # ✅ Post-Quantum Intrusion Detection System (PQ-IDS)
from src.ml_kem import ML_KEM  # ✅ ML-KEM-1024 (FIPS 206)
from src.slh_dsa import SLHDSA  # ✅ SLH-DSA (FIPS 205)

# ✅ Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestPostQuantumIntrusionDetection(unittest.TestCase):
    """✅ Tests for the Intrusion Detection System (IDS) against post-quantum MITM attacks."""

    def setUp(self):
        """✅ Set up test data using ML-KEM-1024 and SLH-DSA for authentication."""
        self.peer = "peer_A"

        # ✅ Generate secure key pair using ML-KEM-1024
        self.pk, self.sk = ML_KEM.generate_keypair()
        self.ciphertext, self.shared_secret = ML_KEM.encapsulate(self.pk)

        # ✅ Generate SLH-DSA Signature
        self.slh_dsa_pub, self.slh_dsa_priv = SLHDSA.generate_keypair()
        self.signature = SLHDSA.sign_message(self.shared_secret, self.slh_dsa_priv)

        # ✅ Tampered secret (MITM attack scenario)
        self.tampered_secret = b"malicious_secret"
        self.tampered_signature = SLHDSA.sign_message(self.tampered_secret, self.slh_dsa_priv)

    @patch("src.intrusion_detection.IDS.log_anomaly")  # ✅ Mock external logging function
    def test_post_quantum_mitm_detection(self, mock_log_anomaly):
        """✅ Ensure IDS detects post-quantum MITM attacks using ML-KEM & SLH-DSA."""

        # ✅ Test that original shared secret passes authentication
        result_original = IDS.detect_anomalies(self.shared_secret, self.signature, self.peer, self.slh_dsa_pub)
        self.assertTrue(result_original, "❌ Original secret should pass verification!")

        # ✅ Test that altered shared secret is flagged as an anomaly
        result_tampered = IDS.detect_anomalies(self.tampered_secret, self.tampered_signature, self.peer, self.slh_dsa_pub)
        self.assertFalse(result_tampered, "❌ Tampered secret should be flagged as MITM attack!")

        # ✅ Ensure that an anomaly is logged in the system
        mock_log_anomaly.assert_called_with(self.peer, self.tampered_secret)

        logging.info("✅ Post-Quantum MITM Attack Detection Test Passed.")

if __name__ == "__main__":
    unittest.main()