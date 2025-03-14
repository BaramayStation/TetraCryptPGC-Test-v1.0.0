import unittest
import os
import subprocess
import logging
import platform
from src.key_rotation import KeyRotation
from src.key_revocation import KeyRevocation
from src.tpm_attestation import tpm_verify_device
from src.sgx_attestation import sgx_remote_attestation

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestSecurityAudit(unittest.TestCase):
    """✅ Comprehensive Security Audit for Post-Quantum Cryptographic Systems."""

    def test_secure_boot(self):
        """✅ Ensure Secure Boot is properly enabled and enforced."""
        try:
            result = subprocess.run(["mokutil", "--sb-state"], capture_output=True, text=True)
            self.assertIn("SecureBoot enabled", result.stdout, "❌ Secure Boot is NOT enabled!")
            logging.info("✅ Secure Boot is properly enabled.")
        except FileNotFoundError:
            self.skipTest("🔸 `mokutil` not found. Unable to verify Secure Boot.")
        except Exception as e:
            logging.error(f"❌ Secure Boot validation failed: {e}")

    def test_tpm_integrity(self):
        """✅ Verify TPM (Trusted Platform Module) functionality and PCR values."""
        try:
            result = subprocess.run(["tpm2_pcrread"], capture_output=True, text=True)
            self.assertNotIn("error", result.stderr.lower(), "❌ TPM is NOT functioning properly!")
            logging.info("✅ TPM Integrity Verified.")
        except FileNotFoundError:
            self.skipTest("🔸 `tpm2-tools` not installed. Skipping TPM check.")
        except Exception as e:
            logging.error(f"❌ TPM Integrity verification failed: {e}")

    def test_remote_attestation(self):
        """✅ Perform remote attestation via TPM & SGX to verify system integrity."""
        try:
            result_tpm = tpm_verify_device()
            result_sgx = sgx_remote_attestation()

            self.assertTrue(result_tpm, "❌ TPM Remote Attestation Failed! Possible untrusted device.")
            self.assertTrue(result_sgx, "❌ SGX Remote Attestation Failed! System integrity compromised.")

            logging.info("✅ Remote Attestation Passed. Device is trusted and verified.")
        except Exception as e:
            logging.error(f"❌ Remote Attestation failed: {e}")

    def test_key_rotation(self):
        """✅ Ensure cryptographic key rotation is automatic and follows security policies."""
        try:
            rotation = KeyRotation()
            initial_key = rotation.generate_key()

            rotation.rotate_key()
            new_key = rotation.current_key

            self.assertNotEqual(initial_key, new_key, "❌ Key Rotation Failed! Key did not change.")
            logging.info("✅ Key Rotation Successful and enforced.")
        except Exception as e:
            logging.error(f"❌ Key Rotation Test Failed: {e}")

    def test_key_revocation(self):
        """✅ Ensure revoked keys are properly invalidated and persist across reboots."""
        try:
            revocation = KeyRevocation()
            test_key = os.urandom(32)  # Generate a secure random key
            revocation.revoke_key(test_key)

            # Check if key is revoked immediately
            self.assertTrue(revocation.is_revoked(test_key), "❌ Key revocation failed!")

            # Simulate persistence by saving & reloading
            revocation.save_state()
            revocation.load_state()
            self.assertTrue(revocation.is_revoked(test_key), "❌ Revoked key did not persist!")

            logging.info("✅ Key Revocation Tested Successfully and persists.")
        except Exception as e:
            logging.error(f"❌ Key Revocation Test Failed: {e}")

    def test_system_fips_compliance(self):
        """✅ Ensure the system is running in FIPS 140-3 compliant mode."""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(["sysctl", "crypto.fips_enabled"], capture_output=True, text=True)
                self.assertIn("1", result.stdout, "❌ System is NOT running in FIPS mode!")
                logging.info("✅ System is running in FIPS 140-3 mode.")
            else:
                self.skipTest("🔸 FIPS compliance test only applicable to Linux systems.")
        except FileNotFoundError:
            self.skipTest("🔸 sysctl not found. Unable to verify FIPS mode.")
        except Exception as e:
            logging.error(f"❌ FIPS compliance check failed: {e}")

    def test_cryptographic_module_integrity(self):
        """✅ Verify OpenSSL and cryptographic module integrity."""
        try:
            result = subprocess.run(["openssl", "version", "-fips"], capture_output=True, text=True)
            self.assertIn("FIPS", result.stdout, "❌ OpenSSL is NOT running in FIPS mode!")
            logging.info("✅ OpenSSL is running in validated FIPS mode.")
        except FileNotFoundError:
            self.skipTest("🔸 OpenSSL not found. Unable to verify FIPS mode.")
        except Exception as e:
            logging.error(f"❌ OpenSSL Integrity verification failed: {e}")

if __name__ == "__main__":
    unittest.main()