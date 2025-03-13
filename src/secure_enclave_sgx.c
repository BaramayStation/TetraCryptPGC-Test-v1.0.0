#include "sgx_trts.h"
#include "sgx_tseal.h"
#include <string.h>
#include <stdio.h>

// 🔹 Define Maximum SGX Seal Key Size (Configurable)
#define SGX_SEAL_KEY_SIZE 32  // Supports 256-bit keys

/**
 * Securely store a cryptographic key inside an SGX enclave.
 * Uses SGX sealing for protection against memory attacks.
 */
sgx_status_t secure_store_key(const unsigned char *key, size_t key_size, unsigned char *sealed_data) {
    if (!key || !sealed_data || key_size == 0 || key_size > SGX_SEAL_KEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // 🔹 Compute required sealed data size
    uint32_t sealed_size = sgx_calc_sealed_data_size(0, key_size);
    if (sealed_size == UINT32_MAX) {
        return SGX_ERROR_UNEXPECTED;
    }

    // 🔹 Securely Seal the Key
    sgx_status_t status = sgx_seal_data(0, NULL, key_size, key, sealed_size, (sgx_sealed_data_t *)sealed_data);
    
    if (status != SGX_SUCCESS) {
        printf("[SGX ERROR] Key sealing failed with status: %d\n", status);
    }

    return status;
}

/**
 * Securely retrieve a cryptographic key from an SGX enclave.
 * Unseals the key while ensuring data integrity.
 */
sgx_status_t retrieve_secure_key(const unsigned char *sealed_data, unsigned char *unsealed_key, size_t key_size) {
    if (!sealed_data || !unsealed_key || key_size == 0 || key_size > SGX_SEAL_KEY_SIZE) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t decrypted_size = key_size;

    // 🔹 Unseal the Stored Key
    sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, 0, unsealed_key, &decrypted_size);
    
    if (status != SGX_SUCCESS) {
        printf("[SGX ERROR] Key unsealing failed with status: %d\n", status);
    }

    return status;
}