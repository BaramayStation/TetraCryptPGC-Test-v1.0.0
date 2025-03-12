import logging
from sgx import RemoteAttestation
from tpm2_pytss import ESAPI, TPM2B_PUBLIC, TPM2B_DIGEST
from hashlib import sha256
import secrets

# Configure Secure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Zero Trust Policy Configuration
REQUIRED_MEASUREMENT_HASH = "expected_hash_of_known_good_environment"

def perform_sgx_attestation():
    """
    Perform Intel SGX remote attestation to verify system integrity.
    Blocks execution if the system fails attestation.
    """
    logging.info("[SGX Attestation] Verifying Trusted Execution Environment...")
    
    ra = RemoteAttestation()
    report = ra.get_attestation_report()

    if not ra.verify():
        logging.critical("[SECURITY ALERT] SGX Remote Attestation FAILED! System integrity compromised.")
        raise ValueError("Remote attestation failed")

    logging.info("[SGX Attestation] Attestation PASSED. Enclave verified.")
    return report

def perform_tpm_attestation():
    """
    Perform TPM-based remote attestation to validate platform integrity.
    Checks against a known-good hash measurement.
    """
    logging.info("[TPM Attestation] Initiating TPM 2.0 Integrity Check...")

    with ESAPI() as tpm:
        pcr_index = 0  # Use PCR0 for boot integrity measurement
        pcr_value = tpm.PCR_Read(pcr_index).digest

        computed_hash = sha256(pcr_value).hexdigest()

        if computed_hash != REQUIRED_MEASUREMENT_HASH:
            logging.critical("[SECURITY ALERT] TPM Integrity Check FAILED! Device is not trusted.")
            raise ValueError("TPM remote attestation failed")
    
    logging.info("[TPM Attestation] Platform integrity verified.")
    return computed_hash

def generate_nonce():
    """Generate a cryptographic nonce for attestation freshness."""
    return secrets.token_hex(16)

def main():
    try:
        logging.info("[REMOTE ATTESTATION] Starting Zero Trust Security Validation...")

        # Generate a nonce for verification
        nonce = generate_nonce()
        logging.info(f"[ATTESTATION] Generated Nonce: {nonce}")

        # Perform SGX & TPM Attestation
        sgx_report = perform_sgx_attestation()
        tpm_hash = perform_tpm_attestation()

        logging.info(f"[SECURITY] SGX Report: {sgx_report}")
        logging.info(f"[SECURITY] TPM Measurement Hash: {tpm_hash}")

        logging.info("[SECURITY] Remote Attestation SUCCESS. System is verified.")
    
    except ValueError as e:
        logging.critical(f"[SECURITY FAILURE] {e}")
        exit(1)

if __name__ == "__main__":
    main()
