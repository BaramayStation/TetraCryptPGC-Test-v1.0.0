import unittest
import os
import subprocess
import logging
from src.key_rotation import KeyRotation
from src.key_revocation import KeyRevocation
from src.tpm_attestation import tpm_verify_device

# 🔹 Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestSecurityAudit(unittest.TestCase):

    def test_secure_boot(self):
        """Ensure Secure Boot is properly enabled."""
        try:
            result = subprocess.run(["mokutil", "--sb-state"], capture_output=True, text=True)
            self.assertIn("SecureBoot enabled", result.stdout, "❌ Secure Boot is NOT enabled!")
            logging.info("✅ Secure Boot is properly enabled.")
        except FileNotFoundError:
            self.skipTest("🔸 `mokutil` not found. Unable to verify Secure Boot.")

    def test_tpm_integrity(self):
        """Verify TPM (Trusted Platform Module) is operational."""
        try:
            result = subprocess.run(["tpm2_pcrread"], capture_output=True, text=True)
            self.assertNotIn("error", result.stderr.lower(), "❌ TPM is NOT functioning properly!")
            logging.info("✅ TPM Integrity Verified.")
        except FileNotFoundError:
            self.skipTest("🔸 `tpm2-tools` not installed. Skipping TPM check.")

    def test_remote_attestation(self):
        """Perform remote attestation via TPM & SGX."""
        result = tpm_verify_device()
        self.assertTrue(result, "❌ Remote Attestation Failed! Possible untrusted device.")
        logging.info("✅ Remote Attestation Passed. Device is trusted.")

    def test_key_rotation(self):
        """Ensure cryptographic key rotation follows security policies."""
        rotation = KeyRotation()
        initial_key = rotation.generate_key()

        rotation.rotate_key()
        new_key = rotation.current_key

        self.assertNotEqual(initial_key, new_key, "❌ Key Rotation Failed! Key did not change.")
        logging.info("✅ Key Rotation Successful.")

    def test_key_revocation(self):
        """Ensure revoked keys are properly invalidated and persist."""
        revocation = KeyRevocation()
        test_key = os.urandom(32)  # Generate a secure random key
        revocation.revoke_key(test_key)

        # Check if key is revoked immediately
        self.assertTrue(revocation.is_revoked(test_key), "❌ Key revocation failed!")

        # Simulate persistence by saving & reloading
        revocation.save_state()
        revocation.load_state()
        self.assertTrue(revocation.is_revoked(test_key), "❌ Revoked key did not persist!")

        logging.info("✅ Key Revocation Tested Successfully.")

if __name__ == "__main__":
    unittest.main()