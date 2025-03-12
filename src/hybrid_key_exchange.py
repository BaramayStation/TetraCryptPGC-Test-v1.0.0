import hashlib
import secrets
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.ecc_hybrid import ecc_keygen, ecc_exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_final_key(shared_secrets):
    """Derive a final hybrid key using HKDF with multiple shared secrets."""
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,  # 512-bit session key
        salt=None,
        info=b"Hybrid Key Exchange"
    )
    return hkdf.derive(shared_secrets)

def hybrid_key_exchange():
    """Perform a hybrid key exchange using both Kyber-1024 and ECC for transition security."""

    # Generate Kyber and ECC key pairs for Alice
    alice_pk_kyber, _ = kyber_keygen()
    alice_sk_ecc, alice_pk_ecc = ecc_keygen()

    # Generate Kyber and ECC key pairs for Bob
    _, _ = kyber_keygen()  # Unused Kyber keys replaced with "_"
    bob_sk_ecc, bob_pk_ecc = ecc_keygen()

    # Kyber Key Encapsulation
    ciphertext, kyber_shared_secret_bob = kyber_encapsulate(alice_pk_kyber)
    kyber_shared_secret_alice = kyber_decapsulate(ciphertext, _)

    # ECC Key Exchange
    ecc_shared_secret_alice = ecc_exchange(alice_sk_ecc, bob_pk_ecc)
    ecc_shared_secret_bob = ecc_exchange(bob_sk_ecc, alice_pk_ecc)

    # Final Key Derivation
    final_key = derive_final_key(kyber_shared_secret_alice + ecc_shared_secret_alice)

    return final_key

if __name__ == "__main__":
    secure_key = hybrid_key_exchange()
    print(f"Derived Secure Hybrid Key: {secure_key.hex()}")
