# Use the latest Ubuntu LTS as the base image
FROM ubuntu:24.04

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for Python, CFFI, and building PQCLEAN
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-cffi \
    build-essential \
    cmake \
    clang \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Clone PQCLEAN repository to ensure we have the source code
RUN git clone --depth 1 https://github.com/PQClean/PQClean.git /app/PQClean

# Compile PQCLEAN with shared libraries
WORKDIR /app/PQClean
RUN mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release .. && \
    make && \
    mkdir -p /app/lib && \
    cp ./crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so /app/lib/ && \
    cp ./crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so /app/lib/

# Set environment variables for library paths
ENV KYBER_LIB_PATH=/app/lib/libpqclean_kyber1024_clean.so
ENV FALCON_LIB_PATH=/app/lib/libpqclean_falcon1024_clean.so
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# Copy the application and test files
COPY ./src/handshake.py /app/
COPY ./src/kyber_kem.py /app/
COPY ./src/falcon_sign.py /app/
COPY ./tests/testhandshake.py /app/
COPY ./requirements.txt /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Set the working directory for running the script
WORKDIR /app

# Set the entrypoint to run the tests by default
CMD ["python3", "-m", "unittest", "testhandshake.py"]
