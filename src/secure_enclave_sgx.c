#include "sgx_trts.h"
#include <string.h>

sgx_status_t secure_store_key(unsigned char *key, size_t key_size, unsigned char *sealed_data) {
    return sgx_seal_data(0, NULL, key_size, key, key_size + SGX_SEAL_KEY_SIZE, sealed_data);
}

sgx_status_t retrieve_secure_key(unsigned char *sealed_data, unsigned char *unsealed_key) {
    uint32_t unsealed_size = 32;
    return sgx_unseal_data(sealed_data, NULL, 0, unsealed_key, &unsealed_size);
}
