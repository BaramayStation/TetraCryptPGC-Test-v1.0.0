import logging

# Configure Logging
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Base Error Class for TetraCryptPGC
class TetraError(Exception):
    """Base exception for all TetraCryptPGC errors."""
    def __init__(self, message, context=None):
        self.message = message
        self.context = context  # Optional: Extra debugging info
        super().__init__(message)

    def __str__(self):
        if self.context:
            return f"{self.message} | Context: {self.context}"
        return self.message


# 🔹 Subclasses for Specific Failure Types
class TetraHandshakeError(TetraError):
    """Raised when handshake verification fails."""
    pass

class TetraSecurityError(TetraError):
    """Raised for security policy violations (e.g., key revocation, intrusion detection)."""
    pass

class TetraEncryptionError(TetraError):
    """Raised for encryption or decryption failures."""
    pass


# 🔹 Example: Validating a Handshake
def verify_handshake(signature, expected_signature):
    """Verify handshake authentication."""
    if signature != expected_signature:
        logging.error("Handshake verification failed! Potential MITM attack.")
        raise TetraHandshakeError("Invalid handshake data", context={"received_sig": signature, "expected_sig": expected_signature})

# 🔹 Example: Handling a Security Violation
def detect_intrusion(anomaly_score):
    """Detect security anomalies."""
    if anomaly_score > 0.9:  # Adjust threshold as needed
        logging.critical("Intrusion detected! Anomaly score exceeds threshold.")
        raise TetraSecurityError("Potential intrusion detected", context={"anomaly_score": anomaly_score})


# 🔹 Test Cases
if __name__ == "__main__":
    try:
        verify_handshake("fake_signature", "real_signature")
    except TetraError as e:
        print(f"Error: {e}")

    try:
        detect_intrusion(0.95)
    except TetraError as e:
        print(f"Security Alert: {e}")
