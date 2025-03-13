import logging
import traceback

# 🔹 Secure Logging Configuration
logging.basicConfig(
    level=logging.WARNING, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# 🔹 Base Error Class for TetraCryptPGC
class TetraError(Exception):
    """Base exception for all TetraCryptPGC errors."""
    def __init__(self, message, context=None):
        self.message = message
        self.context = context  # Extra debugging info (dictionary)
        super().__init__(message)

    def __str__(self):
        error_info = f"{self.message}"
        if self.context:
            error_info += f" | Context: {self.context}"
        return error_info


# 🔹 Specific Exception Types for Cryptographic and Security Failures
class TetraHandshakeError(TetraError):
    """Raised when handshake verification fails."""
    pass

class TetraSecurityError(TetraError):
    """Raised for security policy violations (e.g., key revocation, intrusion detection)."""
    pass

class TetraEncryptionError(TetraError):
    """Raised for encryption or decryption failures."""
    pass

class TetraIntegrityError(TetraError):
    """Raised when data integrity verification fails."""
    pass

class TetraRateLimitError(TetraError):
    """Raised when API rate limits are exceeded to prevent abuse."""
    pass

class TetraInvalidOperation(TetraError):
    """Raised when an invalid cryptographic operation is attempted."""
    pass


# 🔹 Example: Validating a Handshake
def verify_handshake(signature, expected_signature):
    """Verify handshake authentication and prevent MITM attacks."""
    try:
        if signature != expected_signature:
            logging.error("❌ Handshake verification failed! Possible MITM attack.")
            raise TetraHandshakeError(
                "Invalid handshake data",
                context={"received_sig": signature, "expected_sig": expected_signature}
            )
        logging.info("✅ Handshake verified successfully.")
    except Exception as e:
        logging.critical(f"Critical Handshake Failure: {e}")
        raise


# 🔹 Example: Handling a Security Violation (Intrusion Detection)
def detect_intrusion(anomaly_score):
    """Detect security anomalies (e.g., threshold-based intrusion detection)."""
    try:
        if anomaly_score > 0.9:  # Threshold tuning for better false-positive rates
            logging.critical("🚨 Intrusion detected! Anomaly score exceeds threshold.")
            raise TetraSecurityError(
                "Potential intrusion detected",
                context={"anomaly_score": anomaly_score}
            )
        logging.info("🔍 System integrity verified. No intrusion detected.")
    except Exception as e:
        logging.warning(f"Security Alert: {e}")
        raise


# 🔹 Example: Data Integrity Verification (Detects Tampering)
def verify_data_integrity(expected_hash, actual_hash):
    """Check if cryptographic hashes match to prevent tampering."""
    try:
        if expected_hash != actual_hash:
            logging.error("❌ Data integrity verification failed! Possible data tampering.")
            raise TetraIntegrityError(
                "Integrity check failed",
                context={"expected_hash": expected_hash, "actual_hash": actual_hash}
            )
        logging.info("✅ Data integrity verified successfully.")
    except Exception as e:
        logging.critical(f"Data Integrity Error: {e}")
        raise


# 🔹 Test Cases for Future-Proofing
if __name__ == "__main__":
    try:
        verify_handshake("fake_signature", "real_signature")
    except TetraError as e:
        print(f"Error: {e}")

    try:
        detect_intrusion(0.95)
    except TetraError as e:
        print(f"Security Alert: {e}")

    try:
        verify_data_integrity("correct_hash", "tampered_hash")
    except TetraError as e:
        print(f"Integrity Check Failed: {e}")