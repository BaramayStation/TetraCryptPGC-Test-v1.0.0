import os

class KeyRotation:
    def __init__(self, rotation_interval=86400):
        """
        Initialize key rotation manager.
        :param rotation_interval: Time in seconds before key rotates (default: 24 hours)
        """
        self.rotation_interval = rotation_interval
        self.current_key = self.generate_new_key()
        self.last_rotation = time.time()

    def generate_new_key(self):
        """Generate a new secure key"""
        return os.urandom(32)

    def get_key(self):
        """Retrieve current key and rotate if expired"""
        if time.time() - self.last_rotation > self.rotation_interval:
            self.current_key = self.generate_new_key()
            self.last_rotation = time.time()
            print("Key rotated for security.")

        return self.current_key

# Example Usage
rotator = KeyRotation(rotation_interval=3600)  # Rotate every 1 hour
rotator.get_key()