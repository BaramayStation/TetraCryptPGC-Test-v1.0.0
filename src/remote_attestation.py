from sgx import RemoteAttestation

def perform_attestation():
    """Perform Intel SGX or TPM remote attestation to verify device integrity."""
    ra = RemoteAttestation()
    if not ra.verify():
        raise ValueError("[SECURITY ALERT] Remote attestation failed! Unauthorized device detected.")
    print("[SECURITY] Device attestation successful. Secure communication allowed.")

if __name__ == "__main__":
    perform_attestation()
