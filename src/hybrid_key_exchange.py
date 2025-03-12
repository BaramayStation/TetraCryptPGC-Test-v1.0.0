import os
import hashlib
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.ecc_hybrid import ecc_keygen, ecc_derive_shared_secret

def hybrid_key_exchange():
    """Perform a hybrid key exchange using Kyber-1024 (PQC) and ECC (X25519)."""

    # Generate Kyber-1024 key pairs for Bob
    _, bob_sk_kyber = kyber_keygen()  # Private key not needed after decapsulation
    bob_pk_kyber, _ = kyber_keygen()

    # Generate Kyber-1024 key pairs for Alice
    pk_kyber_alice, sk_kyber_alice = kyber_keygen()

    # Encapsulate a shared secret from Bob to Alice
    ciphertext, kyber_shared_secret_alice = kyber_encapsulate(pk_kyber_alice)
    kyber_shared_secret_bob = kyber_decapsulate(ciphertext, sk_kyber_alice)

    # Ensure shared secrets match
    assert kyber_shared_secret_alice == kyber_shared_secret_bob, "Kyber key exchange failed!"

    # ECC Key Exchange
    sk_ecc_alice, pk_ecc_alice = ecc_keygen()
    sk_ecc_bob, pk_ecc_bob = ecc_keygen()

    # Compute ECC shared secret
    ecc_shared_secret_alice = ecc_derive_shared_secret(sk_ecc_alice, pk_ecc_bob)
    _ = ecc_derive_shared_secret(sk_ecc_bob, pk_ecc_alice)  # Unused variable replaced with `_`

    # Derive final hybrid key using HKDF
    final_hybrid_key = hashlib.sha3_512(kyber_shared_secret_alice + ecc_shared_secret_alice).digest()

    return final_hybrid_key

if __name__ == "__main__":
    final_key = hybrid_key_exchange()
    print(f"Derived Hybrid Key: {final_key.hex()}")
