# Use a lightweight Ubuntu 24.04 base optimized for large-scale deployments
FROM ubuntu:24.04

# Set non-interactive mode to prevent manual prompts
ENV DEBIAN_FRONTEND=noninteractive

# Define common paths
ENV APP_HOME="/app"
ENV LIB_DIR="$APP_HOME/lib"
ENV PQCLEAN_REPO="https://github.com/PQClean/PQClean.git"

# Install core dependencies for enterprise-scale PQCLEAN builds
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-cffi \
    build-essential \
    cmake \
    clang \
    git \
    pkg-config \
    ninja-build \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for Podman compatibility & security
RUN useradd -m appuser && chown -R appuser $APP_HOME
USER appuser

# Set working directory
WORKDIR $APP_HOME

# Clone PQCLEAN repository (shallow clone for speed)
RUN git clone --depth 1 $PQCLEAN_REPO $APP_HOME/PQClean

# Build Kyber-1024 & Falcon-1024 libraries with optimizations
WORKDIR $APP_HOME/PQClean
RUN mkdir -p build && cd build && \
    cmake -G Ninja -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release .. && \
    ninja && \
    mkdir -p $LIB_DIR && \
    cp ./crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so $LIB_DIR/ && \
    cp ./crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so $LIB_DIR/

# Set environment variables for library paths
ENV KYBER_LIB_PATH=$LIB_DIR/libpqclean_kyber1024_clean.so
ENV FALCON_LIB_PATH=$LIB_DIR/libpqclean_falcon1024_clean.so
ENV LD_LIBRARY_PATH=$LIB_DIR:$LD_LIBRARY_PATH

# Copy application source code & tests (enterprise-scale)
COPY --chown=appuser ./src/ $APP_HOME/src/
COPY --chown=appuser ./tests/ $APP_HOME/tests/
COPY --chown=appuser ./requirements.txt $APP_HOME/

# Install Python dependencies (enterprise-ready)
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r $APP_HOME/requirements.txt

# Create a persistent volume for enterprise logging & data storage
VOLUME ["/data", "/logs"]

# Define entrypoint for enterprise environments
CMD ["python3", "-m", "unittest", "discover", "-s", "tests"]
