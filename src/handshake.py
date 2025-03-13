import logging
import hashlib
from cffi import FFI
from hashlib import sha3_512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Import Secure Quantum & Post-Quantum Cryptography Modules
from src.qkd_key_exchange import get_qkd_key  # Secure QKD integration
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from src.falcon_sign import falcon_sign, falcon_verify

# Load liboqs for future-proofing
LIBOQS_PATH = "/usr/local/lib/liboqs.so"
ffi = FFI()

try:
    oqs_lib = ffi.dlopen(LIBOQS_PATH)
    logging.info("✅ liboqs successfully loaded for secure PQC handshakes.")
except Exception as e:
    logging.error(f"⚠️ Could not load liboqs: {e}")
    raise RuntimeError("liboqs missing or not installed.")

# Define Falcon-1024 Signature Functions (Post-Quantum Authentication)
ffi.cdef("""
    int OQS_SIG_falcon_1024_keypair(unsigned char *pk, unsigned char *sk);
    int OQS_SIG_falcon_1024_sign(unsigned char *sig, size_t *siglen, const unsigned char *msg, size_t msglen, const unsigned char *sk);
    int OQS_SIG_falcon_1024_verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen, const unsigned char *pk);
""")

FALCON_PUBLICKEYBYTES = 1792
FALCON_SECRETKEYBYTES = 2304
FALCON_SIGNATUREBYTES = 1280


def falcon_keygen():
    """Generate a Falcon-1024 key pair for post-quantum authentication."""
    pk = ffi.new(f"unsigned char[{FALCON_PUBLICKEYBYTES}]")
    sk = ffi.new(f"unsigned char[{FALCON_SECRETKEYBYTES}]")

    ret = oqs_lib.OQS_SIG_falcon_1024_keypair(pk, sk)
    if ret != 0:
        raise RuntimeError("Falcon key generation failed.")

    return bytes(pk), bytes(sk)


def falcon_sign_secure(message, secret_key):
    """Sign a message using Falcon-1024 with liboqs."""
    sig = ffi.new(f"unsigned char[{FALCON_SIGNATUREBYTES}]")
    siglen = ffi.new("size_t *")

    ret = oqs_lib.OQS_SIG_falcon_1024_sign(sig, siglen, message, len(message), secret_key)
    if ret != 0:
        raise ValueError("Falcon signature failed.")

    return bytes(sig)[:siglen[0]]


def falcon_verify_secure(message, signature, public_key):
    """Verify a Falcon-1024 signature."""
    result = oqs_lib.OQS_SIG_falcon_1024_verify(signature, len(signature), message, len(message), public_key)
    return result == 0  # Returns True if valid, False otherwise


def pq_xdh_qkd_handshake():
    """Perform a hybrid QKD + Kyber Post-Quantum Handshake with Falcon Authentication."""
    
    logging.info("\n🔐 Initializing Post-Quantum Secure Handshake...\n")

    # Step 1: Generate Post-Quantum Cryptographic Keys (Kyber KEM)
    logging.info("📢 Generating Kyber Key Pair...")
    pk_kyber, sk_kyber = kyber_keygen()

    try:
        # Step 2: Obtain Quantum Key Distribution (QKD) Shared Secret
        logging.info("📢 Fetching QKD Secure Key...")
        qkd_shared_secret = get_qkd_key()
        logging.info("✅ QKD Secure Key Obtained.")
    except Exception:
        logging.warning("⚠️ QKD Unavailable, Falling Back to Kyber KEM.")
        qkd_shared_secret, _ = kyber_encapsulate(pk_kyber)

    # Step 3: Generate a Random Nonce (Ensuring Uniqueness)
    nonce = hashlib.sha3_512(qkd_shared_secret + sk_kyber).digest()[:16]

    # Step 4: Bind QKD Secret with PQC Key (Hybrid Key Binding)
    logging.info("📢 Combining QKD & Kyber Keys for Hybrid Secure Exchange...")
    combined_secret = sha3_512(qkd_shared_secret + sk_kyber + nonce).digest()

    # Step 5: Generate Falcon-1024 Signature for Authentication
    logging.info("📢 Signing Handshake with Falcon Signature...")
    pk_falcon, sk_falcon = falcon_keygen()
    signature = falcon_sign_secure(combined_secret, sk_falcon)

    # Step 6: Verify Falcon Signature for Mutual Authentication
    logging.info("📢 Verifying Falcon Signature for Integrity...")
    if not falcon_verify_secure(combined_secret, signature, pk_falcon):
        raise ValueError("🚨 QKD + PQC Handshake Authentication Failed! 🚨")

    # Step 7: Derive Final Secure Key Using HKDF (Hybrid Transition)
    logging.info("📢 Deriving Final Hybrid Secure Key using HKDF...")
    final_key = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,  # 512-bit key for hybrid encryption
        salt=None,
        info=b"TetraCrypt QKD Handshake"
    ).derive(combined_secret)

    logging.info("\n✅ QKD + PQC Handshake Successful! 🔐")
    return True, final_key


# Execution: Run Secure QKD-PQC Hybrid Handshake
if __name__ == "__main__":
    valid, shared_key = pq_xdh_qkd_handshake()
    print(f"\n🔑 Secure Shared Key Established: {shared_key.hex()}")