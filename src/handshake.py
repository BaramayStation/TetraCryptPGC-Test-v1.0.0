from qkd_key_exchange import get_qkd_key
from kyber_kem import kyber_keygen, kyber_decapsulate
from falcon_sign import falcon_sign, falcon_verify
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from hashlib import sha3_512

# Example: Hashing the transcript
transcript = kyber_public_key + falcon_signature + nonce  # Adjust variables as needed
transcript_hash = sha3_512(transcript).digest()
def pq_xdh_qkd_handshake():
    """Perform a hybrid QKD + Kyber post-quantum handshake."""
    # Step 1: Generate PQC Keys
    pk_kyber, sk_kyber = kyber_keygen()

    # Step 2: Get QKD Key (Quantum-Secure)
    qkd_shared_secret = get_qkd_key()

    # Step 3: Bind QKD Secret to PQC (Hybrid Mode)
    combined_secret = hashlib.sha3_512(qkd_shared_secret + sk_kyber).digest()

    # Step 4: Authenticate Using Falcon Signatures
    signature = falcon_sign(combined_secret, sk_kyber)
    
    # Step 5: Verify Signature
    if not falcon_verify(combined_secret, signature, pk_kyber):
        raise ValueError("QKD Authentication Failed")

    # Step 6: Derive Final Secure Key Using HKDF
    final_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=b"TetraCrypt QKD Handshake"
    ).derive(combined_secret)

    return True, final_key

if __name__ == "__main__":
    valid, shared_key = pq_xdh_qkd_handshake()
    print(f"QKD-Enhanced Handshake Successful: {valid}")
    print(f"Derived Key: {shared_key.hex()}")
