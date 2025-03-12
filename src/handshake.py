from secure_hsm import retrieve_key_from_hsm, store_key_in_hsm
from qkd_key_exchange import quantum_key_exchange, derive_final_shared_secret
from src.kyber_kem import kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_sign, falcon_verify

def pq_xdh_qkd_hsm_handshake():
    """Perform a post-quantum hybrid handshake using QKD, HSM, and Kyber."""

    # 1️⃣ Retrieve Kyber Key from HSM
    sk_kyber = retrieve_key_from_hsm()
    pk_kyber, _ = kyber_keygen()

    # 2️⃣ Perform QKD Key Exchange
    qkd_key_alice, qkd_key_bob = quantum_key_exchange()
    if qkd_key_alice != qkd_key_bob:
        raise ValueError("QKD Key Mismatch - Possible Quantum Interception!")

    # 3️⃣ Perform Kyber Encapsulation
    ciphertext, pqc_secret_alice = kyber_encapsulate(pk_kyber)
    pqc_secret_bob = kyber_decapsulate(ciphertext, sk_kyber)

    # 4️⃣ Hybrid Key Derivation (QKD + PQC)
    transcript = hashlib.sha3_512(ciphertext).digest()
    final_shared_secret = derive_final_shared_secret(qkd_key_alice, pqc_secret_alice, transcript)

    # 5️⃣ Store Final Key in HSM
    store_key_in_hsm(final_shared_secret)

    # 6️⃣ Post-Quantum Signature for Authentication
    sk_falcon = retrieve_key_from_hsm()
    signature = falcon_sign(final_shared_secret, sk_falcon)

    # 7️⃣ Verify Authentication
    valid = falcon_verify(final_shared_secret, signature, pk_kyber)

    return valid, final_shared_secret

if __name__ == "__main__":
    valid, shared_secret = pq_xdh_qkd_hsm_handshake()
    print(f"QKD + HSM + PQC Handshake Successful: {valid}")
