import os
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.ecc_hybrid import ecc_keygen, ecc_key_exchange

def hybrid_key_exchange():
    """Perform hybrid post-quantum key exchange using Kyber and ECC."""
    
    # Kyber Key Exchange
    alice_pk_kyber, alice_sk_kyber = kyber_keygen()
    bob_pk_kyber, _ = kyber_keygen()  # `bob_sk_kyber` is unused, replaced with `_`
    
    ciphertext, kyber_shared_secret_alice = kyber_encapsulate(alice_pk_kyber)
    kyber_shared_secret_bob = kyber_decapsulate(ciphertext, alice_sk_kyber)
    
    # ECC Key Exchange
    alice_pk_ecc, alice_sk_ecc = ecc_keygen()
    bob_pk_ecc, bob_sk_ecc = ecc_keygen()
    
    ecc_shared_secret_alice = ecc_key_exchange(alice_sk_ecc, bob_pk_ecc)
    _ = ecc_key_exchange(bob_sk_ecc, alice_pk_ecc)  # `ecc_shared_secret_bob` is unused, replaced with `_`

    # Final Key Derivation
    derived_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=b"TetraCryptPGC Hybrid Key Exchange"
    ).derive(kyber_shared_secret_alice + ecc_shared_secret_alice)

    return derived_key

if __name__ == "__main__":
    final_key = hybrid_key_exchange()
    print(f"Derived Hybrid Key: {final_key.hex()}")
