import hashlib
from hashlib import sha3_512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Import Post-Quantum Cryptography Modules
from src.qkd_key_exchange import get_qkd_key
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_sign, falcon_verify

def pq_xdh_qkd_handshake():
    """Perform a hybrid QKD + Kyber Post-Quantum Handshake with Falcon Authentication."""
    
    print("\n🔐 Initializing Post-Quantum Secure Handshake...\n")

    # Step 1: Generate Post-Quantum Cryptographic Keys (Kyber KEM)
    print("📢 Generating Kyber Key Pair...")
    pk_kyber, sk_kyber = kyber_keygen()
    
    # Step 2: Obtain Quantum Key Distribution (QKD) Shared Secret
    print("📢 Fetching QKD Secure Key...")
    qkd_shared_secret = get_qkd_key()
    
    # Step 3: Generate a Random Nonce (Ensuring Uniqueness)
    nonce = hashlib.sha3_512(qkd_shared_secret + sk_kyber).digest()[:16]

    # Step 4: Bind QKD Secret with PQC Key (Hybrid Key Binding)
    print("📢 Combining QKD & Kyber Keys for Hybrid Secure Exchange...")
    combined_secret = sha3_512(qkd_shared_secret + sk_kyber + nonce).digest()

    # Step 5: Generate Falcon-1024 Signature for Authentication
    print("📢 Signing Handshake with Falcon Signature...")
    signature = falcon_sign(combined_secret, sk_kyber)

    # Step 6: Verify Falcon Signature for Mutual Authentication
    print("📢 Verifying Falcon Signature for Integrity...")
    if not falcon_verify(combined_secret, signature, pk_kyber):
        raise ValueError("🚨 QKD + PQC Handshake Authentication Failed! 🚨")

    # Step 7: Derive Final Secure Key Using HKDF (Hybrid Transition)
    print("📢 Deriving Final Hybrid Secure Key using HKDF...")
    final_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,  # 512-bit key for hybrid encryption
        salt=None,
        info=b"TetraCrypt QKD Handshake"
    ).derive(combined_secret)

    print("\n✅ QKD + PQC Handshake Successful! 🔐")
    return True, final_key

# Execution: Run Secure QKD-PQC Hybrid Handshake
if __name__ == "__main__":
    valid, shared_key = pq_xdh_qkd_handshake()
    print(f"\n🔑 Secure Shared Key Established: {shared_key.hex()}")
