import idquantique
from idquantique.qkd_client import QKDClient

def real_qkd_exchange():
    """Establishes a real QKD session using ID Quantique SDK"""
    qkd_client = QKDClient(address="192.168.1.100", port=5000)
    secure_key = qkd_client.get_key(length=256)
    return secure_key

if __name__ == "__main__":
    secure_key = real_qkd_exchange()
    print(f"Generated QKD Key: {secure_key.hex()}")
