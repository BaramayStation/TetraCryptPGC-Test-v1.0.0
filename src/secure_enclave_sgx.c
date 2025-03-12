#include "sgx_trts.h"
#include "sgx_tseal.h"
#include <string.h>

// Define SGX seal key size
#define SGX_SEAL_KEY_SIZE 16

/**
 * Securely store a cryptographic key inside an SGX enclave.
 * Uses SGX sealing for protection against memory attacks.
 */
sgx_status_t secure_store_key(unsigned char *key, size_t key_size, unsigned char *sealed_data) {
    if (!key || !sealed_data || key_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Compute required sealed data size
    uint32_t sealed_size = sgx_calc_sealed_data_size(0, key_size);
    if (sealed_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }

    // Seal the key inside SGX enclave
    return sgx_seal_data(0, NULL, key_size, key, sealed_size, (sgx_sealed_data_t *)sealed_data);
}

/**
 * Securely retrieve a cryptographic key from an SGX enclave.
 * Unseals the key while ensuring data integrity.
 */
sgx_status_t retrieve_secure_key(unsigned char *sealed_data, unsigned char *unsealed_key, size_t key_size) {
    if (!sealed_data || !unsealed_key || key_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t decrypted_size = key_size;

    // Unseal the stored key
    return sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, 0, unsealed_key, &decrypted_size);
}
