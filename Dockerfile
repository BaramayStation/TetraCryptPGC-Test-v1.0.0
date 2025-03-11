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

# Copy the application files (pq_xdh.py and requirements.txt)
COPY ./pq_xdh.py /app/
COPY ./requirements.txt /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Set the library path environment variable so Python can find the .so files
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# Set the working directory back to /app for running the script
WORKDIR /app

# Set the entrypoint for the container
CMD ["python3", "pq_xdh.py"]
