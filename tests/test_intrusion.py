import unittest
import hmac
import hashlib
import logging
from unittest.mock import patch
from src.intrusion_detection import IDS  # ✅ Ensure IDS module is correctly implemented

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestIntrusionDetection(unittest.TestCase):
    """✅ Tests for the Intrusion Detection System (IDS) against MITM attacks."""

    def setUp(self):
        """✅ Set up test data for intrusion detection."""
        self.peer = "peer_A"
        self.secret_original = b"initial_secret"
        self.secret_altered = b"altered_secret"

        # ✅ Generate secure HMAC for integrity verification
        self.sig1 = hmac.new(b"shared_key", self.secret_original, hashlib.sha256).digest()
        self.sig2 = hmac.new(b"shared_key", self.secret_altered, hashlib.sha256).digest()

    @patch("src.intrusion_detection.IDS.log_anomaly")  # ✅ Mock external logging function
    def test_mitm_detection(self, mock_log_anomaly):
        """✅ Ensure MITM attack detection works correctly using IDS."""

        # ✅ Test that original secret is NOT flagged as an anomaly
        result_original = IDS.detect_anomalies(self.secret_original, self.sig1, self.peer)
        self.assertTrue(result_original, "❌ Original key should pass verification!")

        # ✅ Test that altered secret IS flagged as an anomaly
        result_altered = IDS.detect_anomalies(self.secret_altered, self.sig2, self.peer)
        self.assertFalse(result_altered, "❌ Altered secret should be flagged as MITM attack!")

        # ✅ Ensure that an anomaly is logged in the system
        mock_log_anomaly.assert_called_with(self.peer, self.secret_altered)

        logging.info("✅ MITM Attack Detection Test Passed.")

if __name__ == "__main__":
    unittest.main()