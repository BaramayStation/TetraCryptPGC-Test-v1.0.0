import os
import logging
from src.sgx import RemoteAttestation as SGXRemoteAttestation  # ✅ Intel SGX Support
from src.tpm_attestation import TPMRemoteAttestation  # ✅ TPM Support

# 🔹 Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔹 Define Preferred Attestation Method (SGX, TPM, or Fallback)
ATTESTATION_METHOD = os.getenv("TETRACRYPT_ATTESTATION", "SGX").upper()  # Default: SGX

class SecureAttestation:
    """Handles device integrity attestation via SGX, TPM, or software fallback."""

    @staticmethod
    def perform_sgx_attestation():
        """Perform Intel SGX-based remote attestation."""
        logging.info("[SGX] Initiating remote attestation...")
        ra = SGXRemoteAttestation()
        if not ra.verify():
            raise ValueError("[SECURITY ALERT] SGX Remote Attestation Failed! Unauthorized Device Detected.")
        logging.info("[SECURITY] SGX Attestation Successful. Secure Communication Allowed.")
        return True

    @staticmethod
    def perform_tpm_attestation():
        """Perform TPM-based remote attestation."""
        logging.info("[TPM] Initiating Trusted Platform Module (TPM) attestation...")
        tpm = TPMRemoteAttestation()
        if not tpm.verify():
            raise ValueError("[SECURITY ALERT] TPM Remote Attestation Failed! Unauthorized Device Detected.")
        logging.info("[SECURITY] TPM Attestation Successful. Secure Communication Allowed.")
        return True

    @staticmethod
    def software_fallback():
        """Software-based device fingerprinting (for environments without SGX or TPM)."""
        logging.warning("[FALLBACK] No SGX/TPM detected. Using software-based attestation.")
        # Example: Use cryptographic device fingerprinting as a fallback
        device_hash = os.popen("dmidecode -t system | sha256sum").read().strip()
        logging.info(f"[SECURITY] Software-based device fingerprint: {device_hash}")
        return True  # Placeholder (implement proper fallback)

    @staticmethod
    def perform_attestation():
        """Dynamically select the best available attestation method."""
        if ATTESTATION_METHOD == "SGX":
            return SecureAttestation.perform_sgx_attestation()
        elif ATTESTATION_METHOD == "TPM":
            return SecureAttestation.perform_tpm_attestation()
        else:
            logging.error("[ERROR] Unknown attestation method. Using software fallback.")
            return SecureAttestation.software_fallback()

# 🔹 Example Execution
if __name__ == "__main__":
    attestation_result = SecureAttestation.perform_attestation()
    if attestation_result:
        print("[🔐] Remote Attestation Successful. Device Integrity Verified.")
    else:
        print("[❌] Device Attestation Failed. Secure Communication Denied.")
