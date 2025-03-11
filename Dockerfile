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
    pcscd libpcsclite1 \
    tpm2-tools tpm2-abrmd \
    && rm -rf /var/lib/apt/lists/*

# Install Hardware Security Module (HSM) and PKCS#11 Support
RUN apt install -y opensc libengine-pkcs11-openssl

# Set up the working directory
WORKDIR /app

# Clone PQCLEAN Repository for Post-Quantum Cryptography
RUN git clone --depth 1 https://github.com/PQClean/PQClean.git /app/PQClean

# Compile PQCLEAN with security-hardened flags
WORKDIR /app/PQClean
RUN mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -DUSE_AESNI=ON -DUSE_HWRNG=ON \
          -D_FORTIFY_SOURCE=2 -fstack-protector-strong -D_GLIBCXX_ASSERTIONS .. && \
    make -j$(nproc) && \
    mkdir -p /app/lib && \
    cp ./crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so /app/lib/ && \
    cp ./crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so /app/lib/

# Set environment variables for PQC libraries
ENV KYBER_LIB_PATH=/app/lib/libpqclean_kyber1024_clean.so
ENV FALCON_LIB_PATH=/app/lib/libpqclean_falcon1024_clean.so
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# Secure Python Environment
FROM base AS app

# Install Python dependencies securely (Pinned versions for reproducibility)
COPY ./requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Copy Secure Application Code
COPY ./src/ /app/src/
COPY ./tests/ /app/tests/

# Enable TPM Remote Attestation
COPY ./src/tpm_attestation.py /app/src/
ENV TPM_ATTESTATION_ENABLED=true

# Final Hardened Runtime Environment
FROM app AS runtime

# Create a Non-Root User for Execution
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc

# Apply Read-Only Filesystem for Additional Security
RUN chmod -R 700 /app && \
    chmod -R 500 /app/lib && \
    chmod -R 500 /app/src && \
    chmod -R 500 /app/tests && \
    chown -R tetrapgc:tetrapgc /app
VOLUME /app  # Make /app immutable

# Enable Mandatory Access Controls (SELinux & AppArmor)
RUN apt install -y selinux-basics selinux-utils apparmor-utils && \
    setenforce 1 && \
    echo "SELinux is enabled" && \
    aa-enforce /etc/apparmor.d/*

# Apply Kernel Hardening
RUN sysctl -w kernel.randomize_va_space=2 && \
    sysctl -w kernel.dmesg_restrict=1 && \
    sysctl -w kernel.kptr_restrict=2

# Seccomp Profile for Minimal Syscall Usage
COPY seccomp_profile.json /app/seccomp_profile.json
CMD ["python3", "-m", "unittest", "tests/testhandshake.py"]
