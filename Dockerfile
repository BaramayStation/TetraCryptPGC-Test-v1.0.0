# Use Ubuntu Minimal LTS (Security-Hardened)
FROM ubuntu:24.04 AS base

# Enable FIPS Mode (Government Compliance)
ENV UBUNTU_FIPS=true
RUN apt update && apt install -y ubuntu-fips && update-crypto-policies --set FIPS

# Install system dependencies for Python, CFFI, and PQCLEAN libraries
RUN apt install -y --no-install-recommends \
    python3 python3-pip python3-cffi \
    build-essential cmake clang git \
    openssl libssl-dev libpkcs11-helper1 \
    pcscd libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

# Install HSM/TPM Support (PKCS#11)
RUN apt install -y opensc libengine-pkcs11-openssl

# Set up the working directory
WORKDIR /app

# Clone PQCLEAN Repository for Post-Quantum Cryptography
RUN git clone --depth 1 https://github.com/PQClean/PQClean.git /app/PQClean

# Compile PQCLEAN libraries with optimizations for FIPS, AES-NI, and Hardware RNG
WORKDIR /app/PQClean
RUN mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -DUSE_AESNI=ON -DUSE_HWRNG=ON .. && \
    make -j$(nproc) && \
    mkdir -p /app/lib && \
    cp ./crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so /app/lib/ && \
    cp ./crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so /app/lib/

# Set environment variables for PQC libraries
ENV KYBER_LIB_PATH=/app/lib/libpqclean_kyber1024_clean.so
ENV FALCON_LIB_PATH=/app/lib/libpqclean_falcon1024_clean.so
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# ✅ Stage 2: Optimized Application Layer (Separate for Security)
FROM base AS app

# Install GPU Acceleration Libraries (NVIDIA CUDA & OpenCL)
RUN apt install -y nvidia-cuda-toolkit ocl-icd-libopencl1 clinfo

# Copy the application code
COPY ./src/ /app/src/
COPY ./tests/ /app/tests/
COPY ./requirements.txt /app/

# Install Python dependencies in a secure virtual environment
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# ✅ Stage 3: Final Hardened Runtime (Production-Ready)
FROM app AS runtime

# Set secure permissions & disable unnecessary services for FIPS compliance
RUN chmod -R 700 /app && \
    chmod -R 500 /app/lib && \
    chmod -R 500 /app/src && \
    chmod -R 500 /app/tests && \
    chown -R root:root /app

# Set the working directory for execution
WORKDIR /app

# Set the default command to run tests and validate PQC handshake
CMD ["/app/venv/bin/python3", "-m", "unittest", "tests/testhandshake.py"]
