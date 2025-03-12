import os
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

def derive_hybrid_key(pqc_secret, ecc_secret, salt):
    """Combine Kyber shared secret and X25519 shared secret into a single cryptographic key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'pqc+ecc-transition',
    )
    return hkdf.derive(pqc_secret + ecc_secret)

def validate_shared_key(ss_A, ss_B):
    """Validate that both parties derive the same shared key."""
    return hmac.compare_digest(ss_A, ss_B)

def pqc_ecc_hybrid_handshake():
    """
    Hybrid Post-Quantum + ECC (X25519) Key Exchange with Mutual Authentication.
    """
    salt = os.urandom(16)  # Secure random salt

    # Step 1: Generate PQC Keys (Kyber + Falcon)
    pk_A_kyber, sk_A_kyber = kyber_keygen()
    pk_A_falcon, sk_A_falcon = falcon_keygen()
    pk_B_kyber, sk_B_kyber = kyber_keygen()
    pk_B_falcon, sk_B_falcon = falcon_keygen()

    # Step 2: Generate ECC Keys (X25519)
    sk_A_ecc = x25519.X25519PrivateKey.generate()
    pk_A_ecc = sk_A_ecc.public_key()
    sk_B_ecc = x25519.X25519PrivateKey.generate()
    pk_B_ecc = sk_B_ecc.public_key()

    # Step 3: PQC Key Exchange (Kyber)
    ciphertext_B, ss_B_pqc = kyber_encapsulate(pk_A_kyber)
    ss_A_pqc = kyber_decapsulate(ciphertext_B, sk_A_kyber)

    # Step 4: ECC Key Exchange (X25519)
    ss_A_ecc = sk_A_ecc.exchange(pk_B_ecc)
    ss_B_ecc = sk_B_ecc.exchange(pk_A_ecc)

    # Step 5: Combine PQC and ECC Secrets
    ss_A = derive_hybrid_key(ss_A_pqc, ss_A_ecc, salt)
    ss_B = derive_hybrid_key(ss_B_pqc, ss_B_ecc, salt)

    # Step 6: Mutual Authentication using Falcon Signatures
    session_id = os.urandom(16)
    timestamp = int(time.time()).to_bytes(8, "big")

    transcript = hashlib.sha256(
        pk_A_kyber + pk_B_kyber + pk_A_ecc.public_bytes_raw() + pk_B_ecc.public_bytes_raw() + timestamp + session_id
    ).digest()

    sig_A = falcon_sign(transcript, sk_A_falcon)
    sig_B = falcon_sign(transcript, sk_B_falcon)

    valid_A = falcon_verify(transcript, sig_A, pk_A_falcon)
    valid_B = falcon_verify(transcript, sig_B, pk_B_falcon)

    if not (valid_A and valid_B):
        raise ValueError("Signature verification failed")

    if not validate_shared_key(ss_A, ss_B):
        raise ValueError("Key agreement failed: Derived keys do not match")

    return True, ss_A

if __name__ == "__main__":
    try:
        success, hybrid_key = pqc_ecc_hybrid_handshake()
        print(f"Hybrid Handshake Successful: {success}")
    except Exception as e:
        print(f"Error: {e}")
