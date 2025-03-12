# Secure Minimalist Base Image with FIPS Support
FROM gcr.io/distroless/cc-debian12:latest AS base

# Enable FIPS 140-3 Compliance
ENV UBUNTU_FIPS=true
RUN apt update && apt install -y ubuntu-fips && update-crypto-policies --set FIPS

# Install dependencies
RUN apt update && apt install -y --no-install-recommends \
    python3 python3-pip python3-cffi \
    build-essential cmake clang git \
    openssl libssl-dev libpkcs11-helper1 \
    pcscd libpcsclite1 \
    tpm2-tools tpm2-abrmd \
    && rm -rf /var/lib/apt/lists/*

# Enable TPM for Secure Boot & Remote Attestation
RUN tpm2_startup --clear && \
    tpm2_pcrread && \
    tpm2_getrandom 32

# Install PQC Libraries (Kyber & Falcon)
RUN git clone --depth 1 https://github.com/PQClean/PQClean.git /app/PQClean

WORKDIR /app/PQClean
RUN mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -DUSE_AESNI=ON -DUSE_HWRNG=ON \
          -D_FORTIFY_SOURCE=2 -fstack-protector-strong -D_GLIBCXX_ASSERTIONS .. && \
    make -j$(nproc) && \
    mkdir -p /app/lib && \
    cp ./crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so /app/lib/ && \
    cp ./crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so /app/lib/

# Harden Runtime Security
FROM base AS runtime

# Non-Root User for Execution
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc

# Apply Mandatory Access Controls
RUN apt install -y selinux-basics selinux-utils apparmor-utils && \
    setenforce 1 && \
    aa-enforce /etc/apparmor.d/*

# Enable Kernel Hardening
RUN sysctl -w kernel.randomize_va_space=2 && \
    sysctl -w kernel.dmesg_restrict=1 && \
    sysctl -w kernel.kptr_restrict=2

# Seccomp Profile
COPY seccomp_profile.json /app/seccomp_profile.json
CMD ["python3", "-m", "unittest", "tests/test_hybrid_handshake.py"]
