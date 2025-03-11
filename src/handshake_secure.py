from src.zero_trust import verify_user
from src.homomorphic_encryption import encrypt_value, compute_secure_sum
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

def secure_handshake(identity: str, token: str):
    """Perform Zero Trust authentication before cryptographic handshake."""
    
    # Zero Trust Authentication
    if not verify_user(identity, token):
        raise ValueError("Zero Trust authentication failed.")

    # Secure Key Exchange (Kyber + Falcon)
    pk_A, sk_A = kyber_keygen()
    pk_B, sk_B = kyber_keygen()
    
    ciphertext, shared_secret_B = kyber_encapsulate(pk_A)
    shared_secret_A = kyber_decapsulate(ciphertext, sk_A)

    # Encrypt Shared Secret for Secure Computation
    enc_ss_A = encrypt_value(shared_secret_A)
    enc_ss_B = encrypt_value(shared_secret_B)

    # Homomorphic Addition of Shared Secrets (Secure Computation)
    enc_final = compute_secure_sum(enc_ss_A, enc_ss_B)

    return enc_final
