# Use minimal FIPS-ready base image
FROM gcr.io/distroless/cc-debian12:latest AS base

# Set up environment variables for rootless execution
ENV OPENSSL_CONF=/app/local/ssl/openssl.cnf
ENV LD_LIBRARY_PATH=/app/local/lib:$LD_LIBRARY_PATH
ENV PATH=/app/local/bin:$PATH

# Install dependencies inside a user directory
RUN apt update && apt install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    build-essential cmake clang git \
    && rm -rf /var/lib/apt/lists/*

# Set up a user-space environment for cryptographic libraries
WORKDIR /app
RUN mkdir -p /app/local && \
    git clone --depth 1 https://github.com/PQClean/PQClean.git /app/PQClean

# Compile PQCLEAN libraries (Kyber-1024, Falcon-1024)
WORKDIR /app/PQClean
RUN mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/app/local .. && \
    make -j$(nproc) && make install

# Install Python dependencies
COPY requirements.txt /app/
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Copy application source code
COPY src/ /app/src/
COPY tests/ /app/tests/

# Create non-root user for security
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
USER tetrapgc

# Set working directory
WORKDIR /app

# Secure Podman execution with Seccomp
CMD ["python3", "-m", "unittest", "discover", "-s", "tests"]
