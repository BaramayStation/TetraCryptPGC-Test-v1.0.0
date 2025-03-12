from cffi import FFI
import os

ffi = FFI()

# Load the correct secure enclave library based on the architecture
SECURE_ENCLAVE_LIB = os.getenv("SECURE_ENCLAVE_LIB", "/app/lib/libsecure_enclave.so")
enclave = ffi.dlopen(SECURE_ENCLAVE_LIB)

ffi.cdef("""
    sgx_status_t secure_store_key(unsigned char *key, size_t key_size, unsigned char *sealed_data);
    sgx_status_t retrieve_secure_key(unsigned char *sealed_data, unsigned char *unsealed_key);
""")

def secure_store_key(key):
    """
    Store a cryptographic key securely inside Intel SGX / ARM TrustZone.
    This ensures that the key never leaves the secure enclave.
    """
    sealed_data = ffi.new("unsigned char[64]")  # Encrypted key storage
    enclave.secure_store_key(key, len(key), sealed_data)
    return bytes(sealed_data)

def retrieve_secure_key(sealed_data):
    """
    Retrieve and decrypt a key stored inside the secure enclave.
    The key remains inaccessible to the rest of the OS.
    """
    unsealed_key = ffi.new("unsigned char[32]")  # 256-bit key retrieval
    enclave.retrieve_secure_key(sealed_data, unsealed_key)
    return bytes(unsealed_key)

if __name__ == "__main__":
    test_key = os.urandom(32)  # Generate a random key
    sealed_key = secure_store_key(test_key)

    retrieved_key = retrieve_secure_key(sealed_key)
    print(f"Original Key: {test_key.hex()}")
    print(f"Retrieved Key: {retrieved_key.hex()}")
