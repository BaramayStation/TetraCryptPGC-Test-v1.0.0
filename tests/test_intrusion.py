import unittest
from src.intrusion_detection import IDS

class TestIntrusionDetection(unittest.TestCase):
    def test_mitm_detection(self):
        """Ensure MITM detection works correctly."""
        peer = "peer_A"
        secret1 = b"initial_secret"
        secret2 = b"altered_secret"

        self.assertTrue(IDS.detect_anomalies(secret1, b"sig1", peer))
        self.assertFalse(IDS.detect_anomalies(secret2, b"sig2", peer))

if __name__ == "__main__":
    unittest.main()
