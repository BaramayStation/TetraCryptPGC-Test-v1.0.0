import time
from src.mfa_auth import authenticate_with_mfa

class ZeroTrustSession:
    def __init__(self, session_timeout=1800, enforce_mfa=True):
        """Initialize Zero Trust security with session expiration & optional MFA."""
        self.session_timeout = session_timeout
        self.enforce_mfa = enforce_mfa
        self.last_auth_time = time.time()

    def require_authentication(self):
        """Require reauthentication if session has expired."""
        if time.time() - self.last_auth_time > self.session_timeout:
            if self.enforce_mfa:
                if not authenticate_with_mfa():
                    raise ValueError("Multi-Factor Authentication failed.")
            self.last_auth_time = time.time()
            return True
        return False
