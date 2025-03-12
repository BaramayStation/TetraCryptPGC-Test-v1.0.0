# Use a specific digest for reproducibility and security
FROM ubuntu:24.04@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
# Replace 'abcdef...' with the actual digest from 'podman inspect ubuntu:24.04'

# Install dependencies securely and minimally
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip build-essential cmake clang git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone and compile PQCLEAN with shared libraries and security flags
RUN git clone https://github.com/PQClean/PQClean.git /pqclean \
    && cd /pqclean \
    && cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -D_FORTIFY_SOURCE=2 . \
    && make -j$(nproc) \
    && mkdir -p /app/lib \
    && cp lib/*.so /app/lib

# Set environment variables for library paths
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# Add a non-root user for security
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc

# Copy application code
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY requirements.txt /app/
COPY main.py /app/  # Replace 'main.py' with your actual entry point file if different

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Switch to non-root user
USER tetrapgc

# Set the working directory
WORKDIR /app

# Set the entry point to run the application
CMD ["python3", "main.py"]
