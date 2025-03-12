from qkd_bb84 import bb84_key_exchange
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

def pq_qkd_handshake():
    """Hybrid Quantum Key Distribution (QKD) + Kyber-1024 Handshake"""
    # 1. Generate QKD-based secure key
    qkd_key = bb84_key_exchange()
    
    # 2. Generate Kyber keypair
    pk_kyber, sk_kyber = kyber_keygen()
    
    # 3. Encrypt the QKD key using Kyber
    ciphertext, ss_encapsulated = kyber_encapsulate(pk_kyber)
    
    # 4. Decapsulate shared key
    ss_decapsulated = kyber_decapsulate(ciphertext, sk_kyber)
    
    # 5. Verify if QKD Key == Decapsulated Kyber Key
    if qkd_key[:len(ss_decapsulated)] != ss_decapsulated.hex():
        raise ValueError("QKD Key Mismatch!")
    
    return True, ss_decapsulated

if __name__ == "__main__":
    valid, shared_secret = pq_qkd_handshake()
    print(f"QKD-Kyber Handshake Successful: {valid}")
