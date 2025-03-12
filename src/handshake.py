from secure_enclave import secure_store_key, retrieve_secure_key
from src.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate

def pq_xdh_sgx_handshake():
    """Perform a post-quantum handshake inside an SGX enclave."""
    
    # Generate Kyber keypair
    pk_kyber, sk_kyber = kyber_keygen()

    # Store the secret key securely in SGX
    sealed_sk = secure_store_key(sk_kyber)

    # Encapsulate the shared secret
    ciphertext, ss_kyber = kyber_encapsulate(pk_kyber)

    # Retrieve the secret key inside SGX and decapsulate
    sk_unsealed = retrieve_secure_key(sealed_sk)
    ss_decapsulated = kyber_decapsulate(ciphertext, sk_unsealed)

    return True, ss_decapsulated

if __name__ == "__main__":
    valid, shared_secret = pq_xdh_sgx_handshake()
    print(f"SGX-Enabled Handshake Successful: {valid}")
