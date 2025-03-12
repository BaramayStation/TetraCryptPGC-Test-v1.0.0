import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from qkd_bb84 import bb84_qkd
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate

def hybrid_qkd_key_exchange():
    """Perform a hybrid QKD + ECC + PQC key exchange."""
    
    # Step 1: Try QKD First (Quantum-Secured Key)
    qkd_shared_key = None
    try:
        qkd_shared_key = bb84_qkd()
        print("[✔] QKD Key Exchange Successful!")
    except Exception as e:
        print(f"[❌] QKD Unavailable. Falling back to Hybrid ECC + PQC. Error: {e}")

    # Step 2: Generate ECC Key Pair (X25519)
    alice_ecc_sk = x25519.X25519PrivateKey.generate()
    alice_ecc_pk = alice_ecc_sk.public_key()
    bob_ecc_sk = x25519.X25519PrivateKey.generate()
    bob_ecc_pk = bob_ecc_sk.public_key()

    # Step 3: Compute ECC Shared Secret
    ecc_shared_secret_alice = alice_ecc_sk.exchange(bob_ecc_pk)
    ecc_shared_secret_bob = bob_ecc_sk.exchange(alice_ecc_pk)

    # Step 4: Generate Kyber-1024 Key Pair
    alice_pk_kyber, alice_sk_kyber = kyber_keygen()
    bob_pk_kyber, bob_sk_kyber = kyber_keygen()

    # Step 5: Encapsulate Kyber Key (Bob → Alice)
    ciphertext, pqc_shared_secret_bob = kyber_encapsulate(alice_pk_kyber)
    pqc_shared_secret_alice = kyber_decapsulate(ciphertext, alice_sk_kyber)

    if pqc_shared_secret_alice != pqc_shared_secret_bob:
        raise ValueError("Kyber-1024 key exchange failed: Shared secrets do not match!")

    # Step 6: Final Key Derivation
    transcript = hashlib.sha3_512(ciphertext).digest()
    final_hybrid_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=transcript,
    ).derive(
        qkd_shared_key if qkd_shared_key else ecc_shared_secret_alice + pqc_shared_secret_alice
    )

    return final_hybrid_key

if __name__ == "__main__":
    hybrid_key = hybrid_qkd_key_exchange()
    print(f"✅ Hybrid QKD Key Exchange Successful! Final Key: {hybrid_key.hex()}")
