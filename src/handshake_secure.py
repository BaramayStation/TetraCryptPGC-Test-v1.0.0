import hashlib
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

def pq_xdh_handshake_mutual():
    """Post-Quantum XDH Handshake with ZKP Authentication."""
    # Step 1: Generate ephemeral key pairs
    pk_A_kyber, sk_A_kyber = kyber_keygen()
    pk_A_falcon, sk_A_falcon = falcon_keygen()
    pk_B_kyber, sk_B_kyber = kyber_keygen()
    pk_B_falcon, sk_B_falcon = falcon_keygen()

    # Step 2: Key Exchange
    ct_B, ss_B_temp = kyber_encapsulate(pk_A_kyber)
    ss_A_temp = kyber_decapsulate(ct_B, sk_A_kyber)

    # Step 3: Generate Transcript for Authentication
    transcript = hashlib.sha256(
        pk_A_kyber + pk_B_kyber + ct_B + pk_A_falcon + pk_B_falcon
    ).digest()

    # Step 4: Sign and Generate ZKP proof
    sig_A, proof_A = falcon_sign(transcript, sk_A_falcon)
    sig_B, proof_B = falcon_sign(transcript, sk_B_falcon)

    # Step 5: Verify Signature and ZKP
    valid_B = falcon_verify(transcript, sig_B, proof_B, pk_B_falcon)
    valid_A = falcon_verify(transcript, sig_A, proof_A, pk_A_falcon)

    if not (valid_A and valid_B):
        raise AuthenticationError("Signature or ZKP verification failed")

    return True, ss_A_temp
