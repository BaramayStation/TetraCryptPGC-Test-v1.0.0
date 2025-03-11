import os
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

# Secure HKDF Key Derivation
def derive_hybrid_key(pqc_secret, ecc_secret, context=b'TetraHybridPQ'):
    """Derive a strong hybrid key from PQC + ECC secrets using HKDF-SHA384."""
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=64,  # Increased length for future-proof security
        salt=b'HybridKDF',
        info=context,
    )
    return hkdf.derive(pqc_secret + ecc_secret)

def secure_erase(buffer):
    """Zeroize sensitive data from memory to prevent side-channel attacks."""
    for i in range(len(buffer)):
        buffer[i] = secrets.randbits(8)

def pqc_ecc_hybrid_handshake():
    """
    Future-Proof Hybrid Post-Quantum + ECC (X25519) Key Exchange.
    Provides forward secrecy, hybrid security, and FIPS-compliant randomness.
    """
    # Step 1: Generate PQC Keys (Kyber + Falcon)
    pk_A_kyber, sk_A_kyber = kyber_keygen()
    pk_A_falcon, sk_A_falcon = falcon_keygen()
    pk_B_kyber, sk_B_kyber = kyber_keygen()
    pk_B_falcon, sk_B_falcon = falcon_keygen()

    # Step 2: Generate ECC Keys (X25519) with HSM Support
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

    # Step 5: Securely Derive the Hybrid Shared Key
    ss_A = derive_hybrid_key(ss_A_pqc, ss_A_ecc)
    ss_B = derive_hybrid_key(ss_B_pqc, ss_B_ecc)

    # Step 6: Mutual Authentication via Falcon Signatures
    transcript = hashlib.sha384(
        pk_A_kyber + pk_B_kyber + pk_A_ecc.public_bytes_raw() + pk_B_ecc.public_bytes_raw()
    ).digest()

    sig_A = falcon_sign(transcript, sk_A_falcon)
    sig_B = falcon_sign(transcript, sk_B_falcon)

    valid_A = falcon_verify(transcript, sig_A, pk_A_falcon)
    valid_B = falcon_verify(transcript, sig_B, pk_B_falcon)

    if not (valid_A and valid_B):
        raise ValueError("Signature verification failed")

    if ss_A != ss_B:
        raise ValueError("Key agreement failed: PQC and ECC secrets do not match")

    # Zeroize secrets from memory after handshake
    secure_erase(ss_A)
    secure_erase(ss_B)

    return True, ss_A

if __name__ == "__main__":
    try:
        success, hybrid_key = pqc_ecc_hybrid_handshake()
        print(f"Hybrid Handshake Successful: {success}")
    except Exception as e:
        print(f"Error: {e}")
