import os
import smartcard.System
from smartcard.util import toHexString

def list_smart_cards():
    """List all connected smart cards."""
    readers = smartcard.System.readers()
    if not readers:
        raise RuntimeError("No smart card readers found.")
    return readers

def authenticate_with_mfa(pin: str) -> bool:
    """Authenticate using a Smart Card and PIN."""
    readers = list_smart_cards()
    conn = readers[0].createConnection()
    conn.connect()
    
    # APDU Command to verify PIN (Example for OpenSC PKCS#11)
    apdu = [0x00, 0x20, 0x00, 0x80, len(pin)] + list(pin.encode('ascii'))
    response, sw1, sw2 = conn.transmit(apdu)

    if (sw1, sw2) == (0x90, 0x00):  # Success
        return True
    else:
        raise ValueError("MFA Authentication Failed")
