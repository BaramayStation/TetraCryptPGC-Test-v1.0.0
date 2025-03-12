import unittest
import os
import subprocess
from src.key_rotation import KeyRotation
from src.key_revocation import KeyRevocation

class TestSecurityAudit(unittest.TestCase):

    def test_secure_boot(self):
        """Ensure Secure Boot is properly enabled."""
        try:
            result = subprocess.run(["mokutil", "--sb-state"], capture_output=True, text=True)
            self.assertIn("SecureBoot enabled", result.stdout, "Secure Boot is NOT enabled.")
        except FileNotFoundError:
            self.skipTest("mokutil not found. Unable to verify Secure Boot.")

    def test_tpm_integrity(self):
        """Verify TPM (Trusted Platform Module) is operational."""
        try:
            result = subprocess.run(["tpm2_pcrread"], capture_output=True, text=True)
            self.assertNotIn("error", result.stderr.lower(), "TPM is NOT functioning properly.")
        except FileNotFoundError:
            self.skipTest("TPM tool (tpm2_pcrread) not installed. Skipping TPM check.")

    def test_key_revocation(self):
        """Ensure revoked keys are properly invalidated and persist."""
        revocation = KeyRevocation()
        test_key = os.urandom(32)  # Generate a secure random key
        revocation.revoke_key(test_key)

        # Check if key is revoked immediately
        self.assertTrue(revocation.is_revoked(test_key), "Key revocation failed.")

        # Simulate saving & reloading (e.g., simulate persistence)
        revocation.save_state()  # If KeyRevocation supports persistence
        revocation.load_state()
        self.assertTrue(revocation.is_revoked(test_key), "Revoked key did not persist.")

if __name__ == "__main__":
    unittest.main()
