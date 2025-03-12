from secure_hsm import retrieve_key_from_hsm
from src.kyber_kem import kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_sign, falcon_verify

def pq_xdh_hsm_handshake():
    """Perform a post-quantum handshake using HSM-stored keys."""
    
    # Retrieve Kyber Private Key from HSM
    sk_kyber = retrieve_key_from_hsm()
    
    # Perform key exchange
    pk_kyber, _ = kyber_keygen()
    ciphertext, ss_kyber = kyber_encapsulate(pk_kyber)
    ss_decapsulated = kyber_decapsulate(ciphertext, sk_kyber)

    # Retrieve Falcon Private Key from HSM
    sk_falcon = retrieve_key_from_hsm()

    # Sign & Verify handshake
    signature = falcon_sign(ss_decapsulated, sk_falcon)
    valid = falcon_verify(ss_decapsulated, signature, pk_kyber)

    return valid, ss_decapsulated

if __name__ == "__main__":
    valid, shared_secret = pq_xdh_hsm_handshake()
    print(f"HSM-Secured Handshake Successful: {valid}")
