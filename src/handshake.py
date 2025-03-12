from hybrid_key_exchange import hybrid_key_exchange
from hybrid_signatures import hybrid_generate_signatures, hybrid_verify_signatures

def pq_xdh_hybrid_handshake():
    """Perform a hybrid post-quantum handshake using ECC + PQC."""

    # Step 1: Hybrid Key Exchange (X25519 + Kyber)
    shared_key = hybrid_key_exchange()

    # Step 2: Hybrid Signatures (Dilithium + Falcon)
    message = b"Hybrid Secure Handshake"
    falcon_sig, falcon_pk, dilithium_sig, dilithium_pk = hybrid_generate_signatures(message)

    # Step 3: Verify Signatures
    valid = hybrid_verify_signatures(message, falcon_sig, falcon_pk, dilithium_sig, dilithium_pk)

    return valid, shared_key

if __name__ == "__main__":
    valid, shared_key = pq_xdh_hybrid_handshake()
    print(f"Hybrid Handshake Successful: {valid}")
