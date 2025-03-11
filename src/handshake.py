import kyber_kem
import falcon_sign

def pq_xdh_handshake_mutual():
    """Perform a mutual-authentication post-quantum XDH handshake with a single shared secret."""
    # Alice's keypairs
    alice_pk_kyber, alice_sk_kyber = kyber_kem.kyber_keygen()
    alice_pk_falcon, alice_sk_falcon = falcon_sign.falcon_keygen()
    # Bob's keypairs
    bob_pk_kyber, bob_sk_kyber = kyber_kem.kyber_keygen()
    bob_pk_falcon, bob_sk_falcon = falcon_sign.falcon_keygen()
    
    # Single exchange: Bob encapsulates using Alice's public key
    ct_bob, ss_bob = kyber_kem.kyber_encapsulate(alice_pk_kyber)
    ss_alice = kyber_kem.kyber_decapsulate(ct_bob, alice_sk_kyber)
    
    # Mutual authentication
    alice_sig = falcon_sign.falcon_sign(ss_alice, alice_sk_falcon)
    bob_sig = falcon_sign.falcon_sign(ss_bob, bob_sk_falcon)
    
    valid_alice = falcon_sign.falcon_verify(ss_bob, alice_sig, alice_pk_falcon)
    valid_bob = falcon_sign.falcon_verify(ss_alice, bob_sig, bob_pk_falcon)
    
    if not (valid_alice and valid_bob):
        raise ValueError("Handshake failed: Authentication invalid")
    if ss_alice != ss_bob:
        raise ValueError("Handshake failed: Shared secrets mismatch")
    
    return True, ss_alice, ss_bob

if __name__ == "__main__":
    try:
        valid, ss_alice, ss_bob = pq_xdh_handshake_mutual()
        print(f"Handshake successful: {valid}")
    except ValueError as e:
        print(f"Error: {e}")
