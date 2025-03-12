import unittest
from src import pq_xdh_handshake_mutual, kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src import falcon_keygen, falcon_sign, falcon_verify

class TestPQXDH(unittest.TestCase):
    def test_key_generation(self):
        """Test Kyber and Falcon key pair generation."""
        pk_kyber_a, sk_kyber_a = kyber_keygen()
        pk_falcon_a, sk_falcon_a = falcon_keygen()
        pk_kyber_b, _sk_kyber_b = kyber_keygen()  # Unused variable replaced with _
        pk_falcon_b, sk_falcon_b = falcon_keygen()

        self.assertEqual(len(pk_kyber_a), 1568, "Kyber public key size mismatch")
        self.assertEqual(len(sk_kyber_a), 3168, "Kyber secret key size mismatch")
        self.assertEqual(len(pk_falcon_a), 1792, "Falcon public key size mismatch")
        self.assertEqual(len(sk_falcon_a), 2304, "Falcon secret key size mismatch")

    def test_encapsulation_decapsulation(self):
        """Test Kyber encapsulation and decapsulation."""
        pk, sk = kyber_keygen()
        ciphertext, ss_encapsulated = kyber_encapsulate(pk)
        ss_decapsulated = kyber_decapsulate(ciphertext, sk)

        self.assertEqual(ss_encapsulated, ss_decapsulated, "Kyber shared secrets do not match")

    def test_signature_verification(self):
        """Test Falcon signing and verification."""
        pk_falcon, sk_falcon = falcon_keygen()
        message = b"Post-Quantum Test Message"
        signature = falcon_sign(message, sk_falcon)

        self.assertTrue(falcon_verify(message, signature, pk_falcon), "Falcon signature verification failed")

    def test_full_handshake(self):
        """Test the full post-quantum XDH handshake."""
        handshake_valid, ss_a, ss_b = pq_xdh_handshake_mutual()

        self.assertTrue(handshake_valid, "Handshake authentication failed")
        self.assertEqual(ss_a, ss_b, "Handshake shared secrets do not match")

if __name__ == "__main__":
    unittest.main()
