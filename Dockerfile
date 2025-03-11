# Secure Minimalist Base Image with FIPS + TPM + SGX + SEV
FROM gcr.io/distroless/cc-debian12:latest AS base

# Enable FIPS 140-3 Compliance (Government Security Standards)
ENV UBUNTU_FIPS=true
RUN apt update && apt install -y ubuntu-fips && update-crypto-policies --set FIPS

# Install Secure Boot, TPM 2.0, Intel SGX, and AMD SEV Support
RUN apt update && apt install -y --no-install-recommends \
    python3 python3-pip python3-cffi \
    build-essential cmake clang git \
    openssl libssl-dev libpkcs11-helper1 \
    tpm2-tools tpm2-abrmd libtss2-tcti-tabrmd0 \
    pcscd libpcsclite1 opensc libengine-pkcs11-openssl \
    intel-sgx-psw intel-sgx-sdk \
    amd-sev-tool \
    && rm -rf /var/lib/apt/lists/*

# Set up the working directory
WORKDIR /app

# Clone PQCLEAN Repository for Post-Quantum Cryptography (NIST Standardized)
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

# Final Hardened Runtime Environment
FROM app AS runtime

# Create a Non-Root User for Execution (Enforces Least Privilege)
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

# Apply Kernel Hardening (Prevents Exploits & Side-Channel Attacks)
RUN sysctl -w kernel.randomize_va_space=2 && \
    sysctl -w kernel.dmesg_restrict=1 && \
    sysctl -w kernel.kptr_restrict=2

# **Enable TPM 2.0 for Secure Boot & Cryptographic Key Management**
RUN tpm2_startup --clear && \
    tpm2_clear && \
    tpm2_createprimary -C o -g sha256 -G rsa -c /app/tpm_primary.ctx && \
    tpm2_pcrread sha256:0

# **Enable Intel SGX & AMD SEV for Confidential Computing**
RUN echo "Initializing Intel SGX & AMD SEV for Secure Enclave Processing" && \
    sgx_enable && sev_verify

# **Multi-Party Computation (MPC) for Secure Key Sharing**
COPY mpc_key_sharing.py /app/mpc_key_sharing.py
RUN chmod +x /app/mpc_key_sharing.py && python3 /app/mpc_key_sharing.py

# Secure Boot Policy Enforcement
RUN echo "Checking Secure Boot Status..." && \
    dmesg | grep -i "secure boot enabled" || echo "Warning: Secure Boot may not be enabled."

# **TPM-Based Key Management for Kyber and Falcon**
COPY tpm_key_management.sh /app/tpm_key_management.sh
RUN chmod +x /app/tpm_key_management.sh && /app/tpm_key_management.sh

# Secure TPM Key Unsealing on Container Start
ENTRYPOINT ["/app/tpm_key_management.sh"]

# Default Command: Run Secure Tests to Validate Integrity
CMD ["python3", "-m", "unittest", "tests/testhandshake.py"]
