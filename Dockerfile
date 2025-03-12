# Build Stage
FROM ubuntu:24.04 AS build
RUN apt update && apt install -y --no-install-recommends \
    python3 python3-pip build-essential cmake clang git libssl-dev \
    libtss2-dev opensc libengine-pkcs11-openssl && \
    rm -rf /var/lib/apt/lists/*
COPY PQClean.tar.gz /app/  # Pre-downloaded
RUN tar -xzf /app/PQClean.tar.gz -C /app/ && cd /app/PQClean && \
    mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -D_FORTIFY_SOURCE=2 .. && \
    make -j$(nproc) && mkdir -p /app/lib && \
    cp crypto_kem/kyber1024/clean/libpqclean_kyber1024_clean.so /app/lib/ && \
    cp crypto_sign/falcon-1024/clean/libpqclean_falcon1024_clean.so /app/lib/
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir QuNetSim==0.1.2 -r /app/requirements.txt

# Runtime Stage
FROM ubuntu:24.04 AS runtime
RUN apt update && apt install -y python3 selinux-basics apparmor-utils && \
    rm -rf /var/lib/apt/lists/*
RUN addgroup --system tetrapgc && adduser --system --ingroup tetrapgc tetrapgc
COPY --from=build /app/lib /app/lib
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY requirements.txt /app/
RUN python3 -m venv /app/venv && /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt
ENV KYBER_LIB_PATH=/app/lib/libpqclean_kyber1024_clean.so
ENV FALCON_LIB_PATH=/app/lib/libpqclean_falcon1024_clean.so
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH
USER tetrapgc
CMD ["/app/venv/bin/python3", "-m", "unittest", "tests/test_hybrid_handshake.py"]
