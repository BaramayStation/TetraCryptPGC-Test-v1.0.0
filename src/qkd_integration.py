import os
import requests
import secrets
import serial  # Required for serial-based QKD
import hashlib
import hmac

# Define available QKD methods
QKD_PROVIDER = os.getenv("QKD_PROVIDER", "bb84")

def get_qkd_key():
    """Retrieve a QKD key dynamically based on provider selection."""
    if QKD_PROVIDER == "bb84":
        return secrets.token_bytes(32)  # Simulated 256-bit QKD key
    elif QKD_PROVIDER == "idquantique":
        return get_qkd_key_idquantique()
    elif QKD_PROVIDER == "serial":
        return get_qkd_key_serial()
    else:
        raise ValueError(f"Unsupported QKD provider: {QKD_PROVIDER}")

def get_qkd_key_idquantique():
    """Retrieve QKD key from ID Quantique system."""
    qkd_api_url = os.getenv("QKD_API_URL", "https://idq-qkd-server/api/key")
    response = requests.get(qkd_api_url, timeout=10)
    if response.status_code == 200:
        return bytes.fromhex(response.json()["key"])
    raise ConnectionError("Failed to fetch QKD key from IDQ.")

def get_qkd_key_serial(port="/dev/ttyUSB0", baudrate=115200):
    """Retrieve a QKD key from a hardware device over serial."""
    with serial.Serial(port, baudrate, timeout=5) as ser:
        return ser.read(32)  # Read 256-bit key

def verify_qkd_key(qkd_key, device_id, shared_secret):
    """Verify QKD key using HMAC for integrity validation."""
    hmac_verifier = hmac.new(device_id.encode(), shared_secret, hashlib.sha3_512)
    return hmac.compare_digest(hmac_verifier.digest(), qkd_key)
