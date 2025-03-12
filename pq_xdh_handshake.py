import hashlib
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.ecc_hybrid import generate_ecc_keypair, derive_ecc_shared_secret
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify
from src.dilithium_sign import dilithium_keygen, dilithium_sign, dilithium_verify
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def pqc_ecc_hybrid_handshake():
    """Perform a hybrid PQC + ECC handshake using Kyber-1024, X25519, Falcon-1024, and Dilithium-3."""
    
    # Generate PQC & ECC keys
    pk_A_kyber, sk_A_kyber = kyber_keygen()
    ecc_A_priv, ecc_A_pub = generate_ecc_keypair()
    
    pk_B_kyber, sk_B_kyber = kyber_keygen()
    ecc_B_priv, ecc_B_pub = generate_ecc_keypair()
    
    # Kyber encapsulation
    ct_B, ss_B_kyber = kyber_encapsulate(pk_A_kyber)
    ss_A_kyber = kyber_decapsulate(ct_B, sk_A_kyber)
    
    # ECC Diffie-Hellman exchange
    ss_A_ecc = derive_ecc_shared_secret(ecc_A_priv, ecc_B_pub)
    ss_B_ecc = derive_ecc_shared_secret(ecc_B_priv, ecc_A_pub)
    
    if ss_A_ecc != ss_B_ecc:
        raise ValueError("ECC key exchange failed.")
    
    # Combine Kyber & ECC shared secrets
    combined_secret = hashlib.sha3_512(ss_A_kyber + ss_A_ecc).digest()
    
    # Falcon & Dilithium key generation
    pk_A_falcon, sk_A_falcon = falcon_keygen()
    pk_A_dilithium, sk_A_dilithium = dilithium_keygen()
    
    pk_B_falcon, sk_B_falcon = falcon_keygen()
    pk_B_dilithium, sk_B_dilithium = dilithium_keygen()
    
    # Create transcript
    transcript = hashlib.sha3_512(
        pk_A_kyber + pk_B_kyber + ct_B + pk_A_falcon + pk_B_falcon + pk_A_dilithium + pk_B_dilithium
    ).digest()
    
    # Sign the transcript with Falcon and Dilithium
    sig_A_falcon = falcon_sign(transcript, sk_A_falcon)
    sig_B_falcon = falcon_sign(transcript, sk_B_falcon)
    
    sig_A_dilithium = dilithium_sign(transcript, sk_A_dilithium)
    sig_B_dilithium = dilithium_sign(transcript, sk_B_dilithium)
    
    # Verify signatures
    if not falcon_verify(transcript, sig_B_falcon, pk_B_falcon):
        raise ValueError("Falcon signature verification failed.")
    
    if not dilithium_verify(transcript, sig_B_dilithium, pk_B_dilithium):
        raise ValueError("Dilithium signature verification failed.")
    
    # Derive final shared secret using HKDF
    final_shared_secret = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=None,
        info=transcript,
    ).derive(combined_secret)
    
    return True, final_shared_secret
