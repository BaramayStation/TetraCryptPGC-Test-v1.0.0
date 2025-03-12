import logging

logging.basicConfig(filename="intrusion_log.txt", level=logging.WARNING)

class IntrusionDetection:
    def __init__(self):
        self.failed_attempts = {}

    def log_failure(self, event, details):
        """Log a security event"""
        logging.warning(f"SECURITY ALERT: {event} - {details}")

    def detect_anomaly(self, user, event):
        """Detect repeated failures and raise alerts"""
        if user not in self.failed_attempts:
            self.failed_attempts[user] = 0
        self.failed_attempts[user] += 1

        if self.failed_attempts[user] > 3:  # Threshold for alert
            self.log_failure("Repeated Authentication Failure", f"User {user} exceeded login attempts")
            print("ALERT: Potential intrusion detected!")

# Example Usage
ids = IntrusionDetection()
ids.detect_anomaly("user123", "Handshake Failure")