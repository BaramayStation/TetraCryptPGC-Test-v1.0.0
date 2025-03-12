import unittest
from src.pq_xdh_handshake import pqc_ecc_hybrid_handshake

class TestHybridHandshake(unittest.TestCase):
    def test_hybrid_handshake(self):
        """Ensure the hybrid PQC + ECC handshake succeeds."""
        valid, shared_secret = pqc_ecc_hybrid_handshake()
        self.assertTrue(valid, "Hybrid handshake authentication failed.")
        self.assertEqual(len(shared_secret), 64, "Shared secret length mismatch.")

if __name__ == "__main__":
    unittest.main()
