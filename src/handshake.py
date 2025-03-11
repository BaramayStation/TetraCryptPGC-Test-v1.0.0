import hashlib
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

def tetrapq_xdh_handshake():
    # Step 1: Key Generation with CSPRNG
    pk_A_kyber, sk_A_kyber = kyber_keygen()
    pk_A_falcon, sk_A_falcon = falcon_keygen()
    pk_B_kyber, sk_B_kyber = kyber_keygen()
    pk_B_falcon, sk_B_falcon = falcon_keygen()
    # Assume pre-existing long-term keys
    pk_A_falcon_long, sk_A_falcon_long = falcon_keygen()  # Simulated
    pk_B_falcon_long, sk_B_falcon_long = falcon_keygen()  # Simulated

    # Step 2 & 3: Key Exchange
    ct_B, ss_B_temp = kyber_encapsulate(pk_A_kyber)
    ss_A_temp = kyber_decapsulate(ct_B, sk_A_kyber)

    # Step 4: Authentication with Transcript
    transcript = hashlib.sha256(
        pk_A_kyber + pk_B_kyber + ct_B + pk_A_falcon + pk_B_falcon +
        pk_A_falcon_long + pk_B_falcon_long
    ).digest()
    sig_A = falcon_sign(transcript, sk_A_falcon)
    sig_B = falcon_sign(transcript, sk_B_falcon)

    # Step 5: Verification and Derivation
    valid_B = falcon_verify(transcript, sig_B, pk_B_falcon)
    valid_A = falcon_verify(transcript, sig_A, pk_A_falcon)
    if not (valid_A and valid_B):
        raise AuthenticationError("Signature verification failed")
    ss_A = hashlib.sha256(ss_A_temp + transcript).digest()
    ss_B = hashlib.sha256(ss_B_temp + transcript).digest()
    if ss_A != ss_B:
        raise KeyMismatchError("Shared secrets do not match")

    return True, ss_A
