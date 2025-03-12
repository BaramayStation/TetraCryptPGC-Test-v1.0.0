from cffi import FFI

ffi = FFI()
sgx = ffi.dlopen("./libsecure_enclave.so")

ffi.cdef("""
    sgx_status_t secure_store_key(unsigned char *key, size_t key_size, unsigned char *sealed_data);
    sgx_status_t retrieve_secure_key(unsigned char *sealed_data, unsigned char *unsealed_key);
""")

def secure_store_key(key):
    """Store key inside SGX enclave."""
    sealed_data = ffi.new("unsigned char[64]")
    sgx.secure_store_key(key, len(key), sealed_data)
    return bytes(sealed_data)

def retrieve_secure_key(sealed_data):
    """Retrieve key from SGX enclave."""
    unsealed_key = ffi.new("unsigned char[32]")
    sgx.retrieve_secure_key(sealed_data, unsealed_key)
    return bytes(unsealed_key)
