import os
import requests
import serial  # Required for some QKD hardware
import hashlib
import secrets

# Define QKD Sources
QKD_PROVIDER = os.getenv("QKD_PROVIDER", "bb84")

def get_qkd_key_bb84():
    """Simulates a QKD BB84 key exchange."""
    key = secrets.token_bytes(32)  # 256-bit quantum-safe key
    return key

def get_qkd_key_idquantique():
    """Retrieves a QKD key from an ID Quantique system."""
    QKD_API_URL = os.getenv("QKD_API_URL", "https://idq-qkd-server/api/key")
    response = requests.get(QKD_API_URL, timeout=10)
    if response.status_code == 200:
        return bytes.fromhex(response.json()["key"])
    raise ConnectionError("Failed to fetch QKD key from IDQ.")

def get_qkd_key_serial(port="/dev/ttyUSB0", baudrate=115200):
    """Reads a quantum key from a hardware QKD device over serial."""
    with serial.Serial(port, baudrate, timeout=5) as ser:
        key = ser.read(32)  # Read a 256-bit key
        return key

def get_qkd_key():
    """Universal QKD key retrieval based on provider selection."""
    if QKD_PROVIDER == "bb84":
        return get_qkd_key_bb84()
    elif QKD_PROVIDER == "idquantique":
        return get_qkd_key_idquantique()
    elif QKD_PROVIDER == "serial":
        return get_qkd_key_serial()
    else:
        raise ValueError("Unsupported QKD provider.")

if __name__ == "__main__":
    key = get_qkd_key()
    print(f"QKD Key: {key.hex()}")