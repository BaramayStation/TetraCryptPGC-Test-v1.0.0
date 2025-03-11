
import unittest
import tetracrypt

class TestTetraCrypt(unittest.TestCase):
    def setUp(self):
        self.public_key, self.private_key = tetracrypt.generate_key()
        self.message = "Hello, Secure World!"

    def test_generate_key(self):
        self.assertTrue(len(self.public_key) > 0)
        self.assertTrue(len(self.private_key) > 0)

    def test_sign_and_verify(self):
        signature = tetracrypt.sign_message(self.message, self.private_key)
        self.assertTrue(tetracrypt.verify_signature(self.message, signature, self.public_key))

    def test_invalid_signature(self):
        fake_signature = "000000" * 10
        self.assertFalse(tetracrypt.verify_signature(self.message, fake_signature, self.public_key))

if __name__ == "__main__":
    unittest.main()
