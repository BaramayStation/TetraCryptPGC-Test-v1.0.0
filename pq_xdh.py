import os
from cffi import FFI

ffi = FFI()
kyber_lib = ffi.dlopen("./libpqclean_kyber1024_clean.so")
falcon_lib = ffi.dlopen("./libpqclean_falcon1024_clean.so")

ffi.cdef("""
    void PQCLEAN_KYBER1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_KYBER1024_CLEAN_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    void PQCLEAN_KYBER1024_CLEAN_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_keypair(unsigned char *pk, unsigned char *sk);
    void PQCLEAN_FALCON1024_CLEAN_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk);
    int PQCLEAN_FALCON1024_CLEAN_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk);
""")

# Constants
KYBER_PUBLICKEYBYTES = 1568
KYBER_SECRETKEYBYTES = 3168
KYBER_CIPHERTEXTBYTES = 1568
FALCON_PUBLICKEYBYTES = 1281
FALCON_SECRETKEYBYTES = 2305
FALCON_SIGNATUREBYTES = 1280

def pq_xdh_keygen():
    """Generate Kyber-1024 keypair."""
    pk = ffi.new("unsigned char[{}]".format(KYBER_PUBLICKEYBYTES))
    sk = ffi.new("unsigned char[{}]".format(KYBER_SECRETKEYBYTES))
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_keypair(pk, sk)
    if len(bytes(pk)) != KYBER_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    return bytes(pk), bytes(sk)

def encapsulate_key(public_key):
    """Encapsulate a shared secret with Kyber-1024."""
    if len(public_key) != KYBER_PUBLICKEYBYTES:
        raise ValueError("Invalid public key size")
    ct = ffi.new("unsigned char[{}]".format(KYBER_CIPHERTEXTBYTES))
    ss = ffi.new("unsigned char[32]")
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_enc(ct, ss, public_key)
    return bytes(ct), bytes(ss)

def decapsulate_key(ciphertext, secret_key):
    """Decapsulate a shared secret with Kyber-1024."""
    if len(ciphertext) != KYBER_CIPHERTEXTBYTES or len(secret_key) != KYBER_SECRETKEYBYTES:
        raise ValueError("Invalid ciphertext or secret key size")
    ss = ffi.new("unsigned char[32]")
    kyber_lib.PQCLEAN_KYBER1024_CLEAN_dec(ss, ciphertext, secret_key)
    return bytes(ss)

def falcon_keygen():
    """Generate Falcon-1024 keypair."""
    pk = ffi.new("unsigned char[{}]".format(FALCON_PUBLICKEYBYTES))
    sk = ffi.new("unsigned char[{}]".format(FALCON_SECRETKEYBYTES))
    falcon_lib.PQCLEAN_FALCON1024_CLEAN_keypair(pk, sk)
    if len(bytes(pk)) != FALCON_PUBLICKEYBYTES or len(bytes(sk)) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid Falcon key sizes")
    return bytes(pk), bytes(sk)

def sign_shared_secret(shared_secret, falcon_sk):
    """Sign a shared secret with Falcon-1024."""
    if len(falcon_sk) != FALCON_SECRETKEYBYTES:
        raise ValueError("Invalid Falcon secret key size")
    sig = ffi.new("unsigned char[{}]".format(FALCON_SIGNATUREBYTES))
    siglen = ffi.new("size_t *")
    falcon_lib.PQCLEAN_FALCON1024_CLEAN_sign(sig, siglen, shared_secret, len(shared_secret), falcon_sk)
    return bytes(sig)[:siglen[0]]

def verify_signature(shared_secret, signature, falcon_pk):
    """Verify a Falcon-1024 signature."""
    if len(falcon_pk) != FALCON_PUBLICKEYBYTES:
        raise ValueError("Invalid Falcon public key size")
    result = falcon_lib.PQCLEAN_FALCON1024_CLEAN_verify(signature, len(signature), shared_secret, len(shared_secret), falcon_pk)
    return result == 0

def pq_xdh_handshake_mutual():
    """Perform a mutual-authentication post-quantum XDH handshake."""
    alice_pk_kyber, alice_sk_kyber = pq_xdh_keygen()
    alice_pk_falcon, alice_sk_falcon = falcon_keygen()
    bob_pk_kyber, bob_sk_kyber = pq_xdh_keygen()
    bob_pk_falcon, bob_sk_falcon = falcon_keygen()
    
    ct_bob, ss_bob = encapsulate_key(alice_pk_kyber)
    ss_alice = decapsulate_key(ct_bob, alice_sk_kyber)
    
    alice_sig = sign_shared_secret(ss_alice, alice_sk_falcon)
    bob_sig = sign_shared_secret(ss_bob, bob_sk_falcon)
    
    valid_alice = verify_signature(ss_bob, alice_sig, alice_pk_falcon)
    valid_bob = verify_signature(ss_alice, bob_sig, bob_pk_falcon)
    
    if not (valid_alice and valid_bob):
        raise ValueError("Handshake failed: Authentication invalid")
    if ss_alice != ss_bob:
        raise ValueError("Handshake failed: Shared secrets mismatch")
    
    return True, ss_alice, ss_bob

if __name__ == "__main__":
    try:
        valid, ss_alice, ss_bob = pq_xdh_handshake_mutual()
        print(f"Handshake successful: {valid}")
    except ValueError as e:
        print(f"Error: {e}")
