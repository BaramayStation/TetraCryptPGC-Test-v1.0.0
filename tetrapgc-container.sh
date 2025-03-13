#!/bin/bash

# ✅ Secure Environment Variables
export FIPS_ENABLED="true"
export SLH_DSA_LIB="/usr/local/lib/libslh_dsa.so"
export LIBOQS_PATH="/usr/local/lib/liboqs.so"
export LD_LIBRARY_PATH="/usr/local/lib:/usr/lib"

# ✅ Define Podman Image & Container Name
IMAGE_NAME="baramaystation/tetrapgc-secure:latest"
CONTAINER_NAME="tetrapgc-container"

# ✅ Stop & Remove Any Existing Container
podman stop $CONTAINER_NAME 2>/dev/null
podman rm $CONTAINER_NAME 2>/dev/null

# ✅ Run Secure Podman Container
podman run -d \
  --name $CONTAINER_NAME \
  --security-opt seccomp=unconfined \
  --security-opt no-new-privileges \
  --cap-drop=ALL \
  --read-only \
  --user 1001:1001 \
  -p 8080:8080 \
  -v /usr/local/lib/libslh_dsa.so:/usr/local/lib/libslh_dsa.so:ro \
  -v /usr/local/lib/liboqs.so:/usr/local/lib/liboqs.so:ro \
  -e FIPS_ENABLED \
  -e LD_LIBRARY_PATH \
  -e SLH_DSA_LIB \
  -e LIBOQS_PATH \
  $IMAGE_NAME
