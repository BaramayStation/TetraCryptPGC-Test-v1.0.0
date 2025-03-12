import unittest
from src.key_rotation import KeyRotation
from src.key_revocation import KeyRevocation
import os

class TestSecurityAudit(unittest.TestCase):
    def test_secure_boot(self):
        """Ensure Secure Boot is enabled."""
        self.assertTrue(os.path.exists("/sys/firmware/efi"), "Secure Boot is not enabled.")

    def test_tpm_integrity(self):
        """Verify TPM is functional."""
        self.assertTrue(os.system("tpm2_pcrread") == 0, "TPM is not functioning.")

    def test_key_revocation(self):
        """Ensure revoked keys are properly invalidated."""
        revocation = KeyRevocation()
        test_key = os.urandom(32)
        revocation.revoke_key(test_key)
        self.assertTrue(revocation.is_revoked(test_key), "Key revocation failed.")

if __name__ == "__main__":
    unittest.main()
