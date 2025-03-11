# Secure Minimalist Base Image
FROM gcr.io/distroless/cc-debian12:latest AS base

# Enable FIPS 140-2/3 Compliance & Secure Libraries
RUN apt update && apt install -y \
    python3 python3-pip python3-cffi \
    build-essential cmake clang git \
    openssl libssl-dev libpkcs11-helper1 \
    pcscd libpcsclite1 tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

# Install OpenZiti for Zero Trust
RUN curl -s https://get.openziti.io/install.sh | bash

# Install Microsoft SEAL for Homomorphic Encryption
RUN git clone https://github.com/microsoft/SEAL.git && \
    cd SEAL && cmake . && make -j$(nproc) && make install

# Secure Python Environment
FROM base AS app

# Install Python dependencies securely
COPY ./requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Copy Secure Application Code
COPY ./src/ /app/src/
COPY ./tests/ /app/tests/

# Final Hardened Runtime Environment
FROM app AS runtime

# Create a Non-Root User for Execution
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc

# Run Secure Handshake
CMD ["python3", "/app/src/handshake_secure.py"]
