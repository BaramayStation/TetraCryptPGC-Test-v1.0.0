import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate

# ---------------- Hybrid ECC + PQC Key Exchange ----------------

def hybrid_key_exchange():
    """Perform a hybrid key exchange using X25519 (ECC) + Kyber (PQC)."""

    # Generate X25519 (ECC) key pairs
    alice_ecc_sk = x25519.X25519PrivateKey.generate()
    alice_ecc_pk = alice_ecc_sk.public_key()
    bob_ecc_sk = x25519.X25519PrivateKey.generate()
    bob_ecc_pk = bob_ecc_sk.public_key()

    # Compute shared ECC secret
    ecc_shared_secret = alice_ecc_sk.exchange(bob_ecc_pk)

    # Generate Kyber (PQC) key pair
    alice_pk_kyber, alice_sk_kyber = kyber_keygen()
    bob_pk_kyber, bob_sk_kyber = kyber_keygen()

    # Encapsulate Kyber key
    ciphertext, pqc_shared_secret_bob = kyber_encapsulate(alice_pk_kyber)
    pqc_shared_secret_alice = kyber_decapsulate(ciphertext, alice_sk_kyber)

    # Derive Final Hybrid Key
    transcript = hashlib.sha3_512(ciphertext).digest()
    final_hybrid_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=transcript,
    ).derive(ecc_shared_secret + pqc_shared_secret_alice)

    return final_hybrid_key

if __name__ == "__main__":
    hybrid_key = hybrid_key_exchange()
    print(f"Hybrid Key Exchange Successful! Final Key: {hybrid_key.hex()}")
