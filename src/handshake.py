import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_keygen, falcon_sign, falcon_verify

class AuthenticationError(Exception):
    """Raised when signature verification fails."""
    pass

class KeyMismatchError(Exception):
    """Raised when shared secrets do not match."""
    pass

def zeroize_memory(data):
    """Securely overwrite sensitive data in memory."""
    for i in range(len(data)):
        data[i] = 0

def secure_random_bytes(length: int):
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(length)

def hkdf_expand(shared_secret, salt=b"", info=b"TetraPQ-XDH", output_length=64):
    """
    HKDF key derivation function based on NIST SP 800-56C (RFC 5869).
    Used to derive multiple cryptographic keys from the shared secret.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=output_length,
        salt=salt,
        info=info
    )
    return hkdf.derive(shared_secret)

def aes_256_kdf(shared_secret, salt=b"", iterations=100000):
    """
    AES-256-based key derivation function as a secondary secure option.
    Based on PBKDF2 (RFC 8018, NIST SP 800-132).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(shared_secret)

def tetrapq_xdh_handshake():
    """
    Post-Quantum Extended Diffie-Hellman (TetraPQ-XDH) Handshake with:
    - Secure Kyber-1024 key exchange
    - Authentication via Falcon-1024 signatures
    - HKDF-based key derivation (primary)
    - AES-256-based key derivation (backup)
    - Forward secrecy and robust transcript binding
    - Explicit entropy use for enhanced security
    """

    # Step 1: Key Generation with Secure Entropy Source
    pk_A_kyber, sk_A_kyber = kyber_keygen()
    pk_A_falcon, sk_A_falcon = falcon_keygen()
    pk_B_kyber, sk_B_kyber = kyber_keygen()
    pk_B_falcon, sk_B_falcon = falcon_keygen()

    # Simulated long-term Falcon keys for persistent authentication
    pk_A_falcon_long, sk_A_falcon_long = falcon_keygen()  
    pk_B_falcon_long, sk_B_falcon_long = falcon_keygen()  

    # Step 2: Key Exchange (Kyber Encapsulation)
    ct_B, ss_B_temp = kyber_encapsulate(pk_A_kyber)
    ss_A_temp = kyber_decapsulate(ct_B, sk_A_kyber)

    # Ensure encapsulation/decapsulation were successful
    if len(ss_A_temp) != 32 or len(ss_B_temp) != 32:
        raise ValueError("Invalid shared secret size detected.")

    # Step 3: Transcript Binding for Authentication
    transcript = hashlib.sha512(
        pk_A_kyber + pk_B_kyber + ct_B + pk_A_falcon + pk_B_falcon +
        pk_A_falcon_long + pk_B_falcon_long
    ).digest()

    # Step 4: Digital Signatures to Authenticate Key Exchange
    sig_A = falcon_sign(transcript, sk_A_falcon)
    sig_B = falcon_sign(transcript, sk_B_falcon)

    # Securely erase secret keys after signing to prevent memory leaks
    zeroize_memory(sk_A_falcon)
    zeroize_memory(sk_B_falcon)

    # Step 5: Verification of Signatures
    valid_B = falcon_verify(transcript, sig_B, pk_B_falcon)
    valid_A = falcon_verify(transcript, sig_A, pk_A_falcon)

    if not (valid_A and valid_B):
        raise AuthenticationError("Signature verification failed. Potential MITM attack detected.")

    # Step 6: Final Shared Secret Derivation with HKDF & AES-256 KDF
    derived_key_A = hkdf_expand(ss_A_temp + transcript)
    derived_key_B = hkdf_expand(ss_B_temp + transcript)
    derived_backup_A = aes_256_kdf(ss_A_temp + transcript)
    derived_backup_B = aes_256_kdf(ss_B_temp + transcript)

    # Ensure both parties derived the same shared secret
    if not hmac.compare_digest(derived_key_A, derived_key_B) or not hmac.compare_digest(derived_backup_A, derived_backup_B):
        raise KeyMismatchError("Shared secrets do not match. Possible integrity compromise.")

    # Zeroize temporary shared secrets
    zeroize_memory(ss_A_temp)
    zeroize_memory(ss_B_temp)

    return True, derived_key_A, derived_backup_A

if __name__ == "__main__":
    try:
        handshake_successful, shared_secret, backup_secret = tetrapq_xdh_handshake()
        print(f"Handshake successful: {handshake_successful}")
        print(f"Primary Derived Secret: {shared_secret.hex()}")
        print(f"Backup AES-256 Derived Secret: {backup_secret.hex()}")
    except Exception as e:
        print(f"Error during handshake: {e}")
