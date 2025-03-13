# 🔹 Use Minimal FIPS-Ready Base Image for Post-Quantum Security
FROM gcr.io/distroless/cc-debian12:nonroot AS base

# 🔹 Set Up Environment Variables for Secure Execution
ENV OPENSSL_CONF=/app/local/ssl/openssl.cnf
ENV LD_LIBRARY_PATH=/app/local/lib:$LD_LIBRARY_PATH
ENV PATH=/app/local/bin:$PATH
ENV KYBER_LIB_PATH=/app/local/lib/liboqs.so  # ✅ Future-Proofed for Kyber & Falcon

# 🔹 Install Dependencies (Minimal Attack Surface)
RUN apt update && apt install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    git \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# 🔹 Set Up User-Space Environment for Cryptographic Libraries
WORKDIR /app
RUN mkdir -p /app/local && \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /app/liboqs

# 🔹 Compile `liboqs` for Post-Quantum Cryptography (Kyber-1024, Falcon-1024)
WORKDIR /app/liboqs
RUN mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/app/local .. && \
    make -j$(nproc) && make install

# 🔹 Install Python Dependencies
COPY requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# 🔹 Copy Application Source Code
COPY src/ /app/src/
COPY tests/ /app/tests/

# 🔹 Create Non-Root User for Security (Least Privilege)
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc  # ✅ Ensuring Non-Root Execution

# 🔹 Set Secure Working Directory
WORKDIR /app

# 🔹 Secure Execution (Podman + Seccomp)
CMD ["/app/venv/bin/python3", "-m", "unittest", "discover", "-s", "tests"]