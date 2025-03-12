import os
import logging
from smartcard.System import readers
from smartcard.util import toHexString

# Enable structured logging for security
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def list_smart_cards():
    """
    List all connected smart card readers.
    Returns:
        List of smart card readers
    """
    try:
        available_readers = readers()
        if not available_readers:
            raise RuntimeError("No smart card readers found.")
        return available_readers
    except Exception as e:
        logging.error("Error listing smart card readers: %s", e)
        return []

def authenticate_with_mfa(pin: str) -> bool:
    """
    Authenticate using a Smart Card and PIN.
    Args:
        pin (str): User-provided PIN for authentication.
    Returns:
        bool: True if authentication is successful, otherwise False.
    """
    try:
        available_readers = list_smart_cards()
        if not available_readers:
            raise RuntimeError("No available smart card readers detected.")

        conn = available_readers[0].createConnection()
        conn.connect()

        logging.info("[✔] Connected to Smart Card Reader: %s", available_readers[0])

        # Convert PIN to ASCII bytes
        if not pin.isdigit() or len(pin) not in [4, 6, 8]:  # Common PIN lengths
            raise ValueError("Invalid PIN format")

        apdu = [0x00, 0x20, 0x00, 0x80, len(pin)] + list(pin.encode("ascii"))
        response, sw1, sw2 = conn.transmit(apdu)

        if (sw1, sw2) == (0x90, 0x00):  # Success
            logging.info("[✔] MFA Authentication Successful")
            return True
        else:
            logging.warning("[❌] MFA Authentication Failed: Invalid PIN")
            return False
    except Exception as e:
        logging.error("Smart Card Authentication Error: %s", e)
        return False

def read_smart_card_uuid():
    """
    Reads a unique identifier from a smart card for verification.
    Returns:
        str: Smart card unique identifier (UUID)
    """
    try:
        available_readers = list_smart_cards()
        if not available_readers:
            raise RuntimeError("No smart card readers found.")

        conn = available_readers[0].createConnection()
        conn.connect()

        logging.info("[✔] Reading Smart Card UUID...")

        # Sample APDU Command to read UUID from card (adjust based on your card specification)
        uuid_apdu = [0x00, 0xCA, 0x00, 0x00, 0x10]
        response, sw1, sw2 = conn.transmit(uuid_apdu)

        if (sw1, sw2) == (0x90, 0x00):  # Success
            uuid_hex = toHexString(response)
            logging.info("[✔] Smart Card UUID: %s", uuid_hex)
            return uuid_hex
        else:
            logging.warning("[❌] Failed to Read Smart Card UUID")
            return None
    except Exception as e:
        logging.error("Smart Card UUID Read Error: %s", e)
        return None

if __name__ == "__main__":
    # Example usage
    user_pin = input("Enter Smart Card PIN: ").strip()
    if authenticate_with_mfa(user_pin):
        print("✅ Authentication Successful!")
        uuid = read_smart_card_uuid()
        print(f"Smart Card UUID: {uuid}" if uuid else "UUID Read Failed")
    else:
        print("❌ Authentication Failed")
