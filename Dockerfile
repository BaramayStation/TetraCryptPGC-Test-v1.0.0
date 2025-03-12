# Install QKD Dependencies
RUN pip install QuNetSim

# Install Cryptographic Libraries
RUN apt install -y libssl-dev libpqcrypto-dev

# Install QKD Libraries
RUN apt install -y libquantum-dev libqkd-dev simulaqron

# Install HSM Support
RUN apt install -y opensc libengine-pkcs11-openssl \
    && systemctl enable pcscd \
    && systemctl start pcscd

# Install Intel SGX and TPM Support
RUN apt install -y libsgx-enclave-common libtss2-dev opensc libengine-pkcs11-openssl
# Install SGX Attestation & TPM
RUN apt install -y libsgx-urts libsgx-quote-ex libtss2-dev

# Enable TPM for Secure Boot
RUN systemctl enable tpm2-abrmd && \
    tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

RUN apt install -y mokutil && \
    echo "Checking Secure Boot status..." && \
    mokutil --sb-state

# Multi-Stage Build for Secure Enterprise Deployment
FROM ubuntu:24.04 AS build

# Enable FIPS & Harden OS
RUN apt update && apt install -y ubuntu-fips && update-crypto-policies --set FIPS

# Install required dependencies
RUN apt install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    build-essential cmake clang git \
    libssl-dev libgmp-dev \
    libpcsclite1 opensc \
    tpm2-tools tpm2-abrmd \
    && rm -rf /var/lib/apt/lists/*

# Install Cloud-Native Tools (Podman & Kubernetes)
RUN apt install -y podman kubectl containerd runc

# Secure container runtime
RUN mkdir -p /run/user/1000 && chown -R 1000:1000 /run/user/1000

# Clone PQCLEAN for Kyber & Falcon
RUN git clone --depth 1 https://github.com/PQClean/PQClean.git /app/PQClean

WORKDIR /app/PQClean
RUN mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release \
    -DUSE_AESNI=ON -DUSE_HWRNG=ON \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong -D_GLIBCXX_ASSERTIONS .. && \
    make -j$(nproc) && \
    mkdir -p /app/lib && \
    cp ./crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so /app/lib/ && \
    cp ./crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so /app/lib/

# Deploy Secure Runtime
FROM ubuntu:24.04 AS runtime

# Set environment variables
ENV KYBER_LIB_PATH=/app/lib/libpqclean_kyber1024_clean.so
ENV FALCON_LIB_PATH=/app/lib/libpqclean_falcon1024_clean.so
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# Harden Runtime Security
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc

# Apply Mandatory Access Controls
RUN apt install -y selinux-basics selinux-utils apparmor-utils && \
    setenforce 1 && \
    aa-enforce /etc/apparmor.d/*

# Copy Secure Application Code
COPY ./src/ /app/src/
COPY ./tests/ /app/tests/
COPY ./requirements.txt /app/

# Install Python dependencies securely
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Run tests inside Podman sandbox
CMD ["podman", "run", "--security-opt", "seccomp=/app/seccomp_profile.json", "--read-only", "python3", "-m", "unittest", "tests/test_hybrid_handshake.py"]
