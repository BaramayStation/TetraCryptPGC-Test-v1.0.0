import unittest
from src import pq_xdh_handshake_mutual, kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src import falcon_keygen, falcon_sign, falcon_verify

class TestPQXDH(unittest.TestCase):
    def test_key_generation(self):
        """Test Kyber and Falcon key pair generation."""
        public_key_kyber_A, secret_key_kyber_A = kyber_keygen()
        public_key_falcon_A, secret_key_falcon_A = falcon_keygen()
        public_key_kyber_B, _secret_key_kyber_B = kyber_keygen()  # Unused variable replaced with _
        public_key_falcon_B, secret_key_falcon_B = falcon_keygen()

        self.assertEqual(len(public_key_kyber_A), 1568, "Kyber public key size mismatch")
        self.assertEqual(len(secret_key_kyber_A), 3168, "Kyber secret key size mismatch")
        self.assertEqual(len(public_key_falcon_A), 1792, "Falcon public key size mismatch")
        self.assertEqual(len(secret_key_falcon_A), 2304, "Falcon secret key size mismatch")

    def test_encapsulation_decapsulation(self):
        """Test Kyber encapsulation and decapsulation."""
        public_key, secret_key = kyber_keygen()
        ciphertext, shared_secret_encapsulated = kyber_encapsulate(public_key)
        shared_secret_decapsulated = kyber_decapsulate(ciphertext, secret_key)

        self.assertEqual(shared_secret_encapsulated, shared_secret_decapsulated, "Kyber shared secrets do not match")

    def test_signature_verification(self):
        """Test Falcon signing and verification."""
        public_key_falcon, secret_key_falcon = falcon_keygen()
        message = b"Post-Quantum Test Message"
        signature = falcon_sign(message, secret_key_falcon)

        self.assertTrue(falcon_verify(message, signature, public_key_falcon), "Falcon signature verification failed")

    def test_full_handshake(self):
        """Test the full post-quantum XDH handshake."""
        handshake_valid, shared_secret_A, shared_secret_B = pq_xdh_handshake_mutual()

        self.assertTrue(handshake_valid, "Handshake authentication failed")
        self.assertEqual(shared_secret_A, shared_secret_B, "Handshake shared secrets do not match")

if __name__ == "__main__":
    unittest.main()
