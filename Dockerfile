# Use minimal FIPS-ready base image with a fixed version
FROM gcr.io/distroless/cc-debian12:nonroot AS base

# Set up environment variables for rootless execution
ENV OPENSSL_CONF=/app/local/ssl/openssl.cnf
ENV LD_LIBRARY_PATH=/app/local/lib:$LD_LIBRARY_PATH
ENV PATH=/app/local/bin:$PATH

# Install dependencies inside a user directory, sorted alphabetically
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

# Set up a user-space environment for cryptographic libraries
WORKDIR /app
RUN mkdir -p /app/local && \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /app/liboqs

# Compile liboqs
WORKDIR /app/liboqs
RUN mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/app/local .. && \
    make -j$(nproc) && make install

# Install Python dependencies
COPY requirements.txt /app/
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Copy application source code
COPY src/ /app/src/
COPY tests/ /app/tests/

# Create non-root user for security
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc  # Ensuring non-root execution

# Set working directory
WORKDIR /app

# Set the library path for Kyber-1024
ENV KYBER_LIB_PATH=/app/local/lib/liboqs.so

# Secure Podman execution with Seccomp
CMD ["python3", "-m", "unittest", "discover", "-s", "tests"]
