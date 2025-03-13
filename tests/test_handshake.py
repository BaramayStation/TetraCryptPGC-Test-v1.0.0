import unittest
import logging
from src.pq_xdh_handshake_mutual import pq_xdh_handshake_mutual
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify
from src.dilithium_sign import dilithium_keygen, dilithium_sign, dilithium_verify

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestPQXDH(unittest.TestCase):
    def test_kyber_key_generation(self):
        """✅ Test Kyber key pair generation."""
        pk, sk = kyber_keygen()
        self.assertEqual(len(pk), 1568, "❌ Kyber public key size mismatch")
        self.assertEqual(len(sk), 3168, "❌ Kyber secret key size mismatch")
        logging.info("✅ Kyber Key Generation Test Passed.")

    def test_falcon_key_generation(self):
        """✅ Test Falcon key pair generation."""
        pk, sk = falcon_keygen()
        self.assertEqual(len(pk), 1792, "❌ Falcon public key size mismatch")
        self.assertEqual(len(sk), 2304, "❌ Falcon secret key size mismatch")
        logging.info("✅ Falcon Key Generation Test Passed.")

    def test_dilithium_key_generation(self):
        """✅ Test Dilithium key pair generation."""
        pk, sk = dilithium_keygen()
        self.assertGreater(len(pk), 0, "❌ Dilithium public key size mismatch")
        self.assertGreater(len(sk), 0, "❌ Dilithium secret key size mismatch")
        logging.info("✅ Dilithium Key Generation Test Passed.")

    def test_kyber_encapsulation_decapsulation(self):
        """✅ Test Kyber encapsulation and decapsulation."""
        pk, sk = kyber_keygen()
        ciphertext, shared_secret_enc = kyber_encapsulate(pk)
        shared_secret_dec = kyber_decapsulate(ciphertext, sk)

        self.assertEqual(shared_secret_enc, shared_secret_dec, "❌ Kyber shared secrets do not match")
        logging.info("✅ Kyber Encapsulation & Decapsulation Test Passed.")

    def test_falcon_signature_verification(self):
        """✅ Test Falcon signing and verification."""
        pk, sk = falcon_keygen()
        message = b"Post-Quantum Test Message"
        signature = falcon_sign(message, sk)

        self.assertTrue(falcon_verify(message, signature, pk), "❌ Falcon signature verification failed")
        logging.info("✅ Falcon Signature Verification Test Passed.")

    def test_dilithium_signature_verification(self):
        """✅ Test Dilithium signing and verification."""
        pk, sk = dilithium_keygen()
        message = b"Post-Quantum Test Message"
        signature = dilithium_sign(message, sk)

        self.assertTrue(dilithium_verify(message, signature, pk), "❌ Dilithium signature verification failed")
        logging.info("✅ Dilithium Signature Verification Test Passed.")

    def test_full_handshake(self):
        """✅ Test the full post-quantum XDH handshake."""
        valid, shared_secret_alice, shared_secret_bob = pq_xdh_handshake_mutual()

        self.assertTrue(valid, "❌ PQXDH Handshake Authentication Failed!")
        self.assertEqual(shared_secret_alice, shared_secret_bob, "❌ PQXDH Handshake shared secrets do not match!")
        logging.info("✅ PQXDH Handshake Test Passed.")

if __name__ == "__main__":
    unittest.main()