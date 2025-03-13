import logging
import time
import hashlib
import os

# 🔹 Configure Secure Logging
logging.basicConfig(
    filename="mfa_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class MultiFactorAuth:
    """
    Multi-Factor Authentication (MFA) System with Smart Card & Biometric Support.
    
    Features:
    - PIN-based authentication (e.g., Smart Cards, YubiKey)
    - Biometric authentication compatibility
    - Rate-limiting to prevent brute-force attacks
    """

    def __init__(self, max_attempts=5, lockout_time=30):
        """
        :param max_attempts: Maximum failed attempts before lockout (default: 5)
        :param lockout_time: Lockout duration in seconds (default: 30s)
        """
        self.failed_attempts = 0
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
        self.last_failed_time = 0

    def authenticate_with_mfa(self, pin: str, user_id: str) -> bool:
        """
        Authenticate using a Smart Card and PIN.
        
        :param pin: User-provided PIN for authentication.
        :param user_id: Unique user identifier for tracking failed attempts.
        :return: True if authentication is successful, False otherwise.
        """

        if self.failed_attempts >= self.max_attempts:
            if time.time() - self.last_failed_time < self.lockout_time:
                logging.warning(f"⛔ User {user_id} locked out due to multiple failed MFA attempts.")
                return False
            else:
                self.failed_attempts = 0  # Reset attempts after lockout period

        try:
            # 🔹 Simulated smart card authentication (replace with actual hardware validation)
            if not self.validate_pin(pin):
                self.failed_attempts += 1
                self.last_failed_time = time.time()
                logging.warning(f"⚠️ User {user_id}: Invalid PIN attempt {self.failed_attempts}/{self.max_attempts}.")
                return False

            logging.info(f"✅ User {user_id} authenticated successfully via MFA.")
            self.failed_attempts = 0  # Reset on success
            return True

        except Exception as e:
            logging.error(f"🚨 MFA authentication error for User {user_id}: {e}")
            return False

    def validate_pin(self, pin: str) -> bool:
        """Simulated PIN validation. Extend this for hardware authentication."""
        return len(pin) >= 4 and pin.isdigit()

    def biometric_authenticate(self, biometric_hash: str, stored_hash: str) -> bool:
        """
        Authenticate using biometric verification.
        
        :param biometric_hash: Hash of user's biometric data (e.g., fingerprint, face scan).
        :param stored_hash: Pre-registered biometric hash.
        :return: True if biometric authentication is successful, False otherwise.
        """
        try:
            if hashlib.sha256(biometric_hash.encode()).hexdigest() == stored_hash:
                logging.info("✅ Biometric authentication successful.")
                return True
            else:
                logging.warning("⚠️ Biometric authentication failed.")
                return False
        except Exception as e:
            logging.error(f"🚨 Biometric authentication error: {e}")
            return False

# 🔹 Example Usage
if __name__ == "__main__":
    mfa = MultiFactorAuth()
    user_id = "user123"

    # Test PIN authentication
    if mfa.authenticate_with_mfa("1234", user_id):
        print("✅ MFA Authentication Successful")
    else:
        print("❌ MFA Authentication Failed")

    # Test biometric authentication
    stored_biometric_hash = hashlib.sha256("fingerprint_sample".encode()).hexdigest()
    if mfa.biometric_authenticate("fingerprint_sample", stored_biometric_hash):
        print("✅ Biometric Authentication Successful")
    else:
        print("❌ Biometric Authentication Failed")