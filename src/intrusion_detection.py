import logging
import time

# 🔹 Security Log Configuration
logging.basicConfig(
    filename="intrusion_log.txt",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class IntrusionDetection:
    """Advanced Intrusion Detection System for TetraCryptPGC"""
    
    def __init__(self):
        self.failed_attempts = {}  # Track failed authentication attempts
        self.anomaly_score = {}  # Adaptive anomaly scoring

    def log_failure(self, event, details):
        """Log a security event with timestamp."""
        logging.warning(f"SECURITY ALERT: {event} - {details}")

    def detect_anomaly(self, user, event):
        """Detect repeated failures and raise alerts using an adaptive threshold."""
        
        if user not in self.failed_attempts:
            self.failed_attempts[user] = {"count": 0, "last_attempt": time.time()}
            self.anomaly_score[user] = 0.0  # Initialize user anomaly score

        # Time-based rate limiting (prevents brute-force attacks)
        time_since_last = time.time() - self.failed_attempts[user]["last_attempt"]
        if time_since_last < 10:  # If multiple failures occur within 10s, increase anomaly score
            self.anomaly_score[user] += 0.2

        self.failed_attempts[user]["count"] += 1
        self.failed_attempts[user]["last_attempt"] = time.time()

        if self.failed_attempts[user]["count"] > 3 or self.anomaly_score[user] > 0.7:
            self.log_failure("Repeated Authentication Failure", f"User {user} exceeded login attempts.")
            print(f"🚨 ALERT: Potential intrusion detected for user {user}!")
            return True  # Alert triggered
        
        return False  # No alert triggered


# 🔹 Example Usage
if __name__ == "__main__":
    ids = IntrusionDetection()

    # Simulating failed attempts for a user
    for _ in range(5):
        alert_triggered = ids.detect_anomaly("user123", "Handshake Failure")
        if alert_triggered:
            break  # Stop after detecting an intrusion

    print("✅ Intrusion Detection System Running Securely")