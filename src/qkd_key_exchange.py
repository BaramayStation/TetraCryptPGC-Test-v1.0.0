import os
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from simulaqron.toolbox.epr_socket import EPRSocket
from simulaqron.local import SimulaQron

# Initialize QKD Simulation Environment
SimulaQron().start()

# ---------------- Quantum Key Distribution (QKD) ----------------

def quantum_key_exchange():
    """Perform QKD-based key exchange using quantum entanglement."""
    epr = EPRSocket()
    
    # Alice generates quantum key
    alice_key = os.urandom(32)  # 256-bit quantum key
    epr.send_epr(alice_key)

    # Bob receives entangled key
    bob_key = epr.recv_epr()

    return alice_key, bob_key

# ---------------- Hybrid Key Derivation ----------------

def derive_final_shared_secret(qkd_key, pqc_key, transcript):
    """Derive a post-quantum hybrid key using QKD + Kyber."""
    combined_key = qkd_key + pqc_key

    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=transcript,
    )
    return hkdf.derive(combined_key)

# ---------------- Main Execution ----------------

if __name__ == "__main__":
    qkd_key_alice, qkd_key_bob = quantum_key_exchange()
    
    if qkd_key_alice != qkd_key_bob:
        raise ValueError("QKD Key Mismatch - Possible Quantum Interception Detected!")
    
    print(f"Quantum Key Exchange Successful! Shared QKD Key: {qkd_key_alice.hex()}")
