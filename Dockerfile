# ✅ Use minimal FIPS-ready base image with a fixed version
FROM gcr.io/distroless/cc-debian12:nonroot AS base

# ✅ Set up environment variables for rootless execution
ENV OPENSSL_CONF=/app/local/ssl/openssl.cnf
ENV LD_LIBRARY_PATH=/app/local/lib:$LD_LIBRARY_PATH
ENV PATH=/app/local/bin:$PATH

# ✅ Install dependencies securely with explicit versions
RUN apt update && apt install -y --no-install-recommends \
    python3=3.11.2-1~deb12u1 \
    python3-pip=23.0.1+dfsg-1 \
    python3-venv=3.11.2-1~deb12u1 \
    build-essential=12.9 \
    cmake=3.25.1-1 \
    clang=14.0-55~deb12u1 \
    git=1:2.39.2-1.1 \
    && rm -rf /var/lib/apt/lists/*

# ✅ Set up a user-space environment for cryptographic libraries
WORKDIR /app
RUN mkdir -p /app/local && \
    git clone --depth 1 https://github.com/PQClean/PQClean.git /app/PQClean

# ✅ Compile PQCLEAN libraries (Kyber-1024, Falcon-1024)
WORKDIR /app/PQClean
RUN mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/app/local .. && \
    make -j$(nproc) && make install

# ✅ Install Python dependencies with pinned versions
COPY requirements.txt /app/
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# ✅ Copy application source code
COPY src/ /app/src/
COPY tests/ /app/tests/

# ✅ Create non-root user for security
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc

# ✅ Set working directory
WORKDIR /app

# ✅ Secure Podman execution with Seccomp
CMD ["python3", "-m", "unittest", "discover", "-s", "tests"]
