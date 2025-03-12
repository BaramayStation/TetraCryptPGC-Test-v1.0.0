import logging

def authenticate_with_mfa(pin: str) -> bool:
    """
    Authenticate using a Smart Card and PIN.

    Args:
        pin (str): User-provided PIN for authentication.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    try:
        # Simulated smart card authentication check
        if len(pin) < 4:  # Example validation rule
            logging.error("Invalid PIN: Too short")
            return False

        logging.info("MFA authentication successful.")
        return True

    except Exception as e:
        logging.error(f"MFA authentication error: {e}")
        return False
