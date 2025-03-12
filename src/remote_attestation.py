from sgx import RemoteAttestation

def perform_attestation():
    """Perform Intel SGX remote attestation to verify system integrity."""
    ra = RemoteAttestation()
    if not ra.verify():
        raise ValueError("Remote attestation failed")
