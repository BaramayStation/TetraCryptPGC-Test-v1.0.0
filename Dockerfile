# Secure Minimalist Base Image
FROM gcr.io/distroless/cc-debian12:latest AS base

# Enable FIPS 140-2/3 Compliance
ENV UBUNTU_FIPS=true
RUN apt update && apt install -y ubuntu-fips && update-crypto-policies --set FIPS

# Install necessary dependencies
RUN apt update && apt install -y --no-install-recommends \
    python3 python3-pip python3-cffi \
    build-essential cmake clang git \
    openssl libssl-dev libpkcs11-helper1 \
    pcscd libpcsclite1 tpm2-tools tpm2-abrmd \
    && rm -rf /var/lib/apt/lists/*

# Install Hardware Security Module (HSM) and PKCS#11 Support
RUN apt install -y opensc libengine-pkcs11-openssl

# Set up the working directory
WORKDIR /app

# Secure Python Environment
FROM base AS app

# Install Python dependencies securely
COPY ./requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Copy Secure Application Code
COPY ./src/ /app/src/
COPY ./tests/ /app/tests/

# Enable TPM Remote Attestation & MFA
COPY ./src/tpm_attestation.py /app/src/
COPY ./src/mfa_auth.py /app/src/
ENV TPM_ATTESTATION_ENABLED=true
ENV MFA_REQUIRED=true

# Secure Key Rotation
COPY ./src/key_rotation.py /app/src/
COPY ./src/key_revocation.py /app/src/
ENV KEY_ROTATION_INTERVAL=2592000  # 30 Days

# Final Hardened Runtime Environment
FROM app AS runtime

# Create a Non-Root User for Execution
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc

# Run Secure Key Rotation Automatically
CMD ["python3", "/app/src/key_rotation.py"]
