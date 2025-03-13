# 🔹 Makefile for Future-Proofed TetraCryptPGC Setup

# ✅ Define Variables
LIBOQS_REPO_URL = https://github.com/open-quantum-safe/liboqs.git
LIBOQS_DIR = lib/liboqs
LIBRARY_PATH = lib/liboqs.so
VENV_DIR = venv
PYTHON = $(VENV_DIR)/bin/python3
PIP = $(VENV_DIR)/bin/pip

# 🔹 Setup: Install Environment & Dependencies
setup:
	@echo "🔹 Setting up the TetraCrypt environment..."
	@python3 -m venv $(VENV_DIR)
	@$(PIP) install --no-cache-dir -r requirements.txt
	@make liboqs

# 🔹 Build: Compile `liboqs` for Post-Quantum Cryptography
liboqs:
	@echo "🔹 Cloning & Building liboqs (Quantum-Safe Cryptography)..."
	@if [ ! -d "$(LIBOQS_DIR)" ]; then \
		git clone --depth 1 $(LIBOQS_REPO_URL) $(LIBOQS_DIR); \
	fi
	@mkdir -p $(LIBOQS_DIR)/build && cd $(LIBOQS_DIR)/build && \
		cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
		make -j$(nproc) && make install

# 🔹 Run Tests: Execute Unit Tests
test:
	@echo "🔹 Running TetraCrypt Tests..."
	@$(PYTHON) -m unittest discover -s tests

# 🔹 Clean: Remove Compiled Libraries & Cache
clean:
	@echo "🧹 Cleaning up build artifacts..."
	@rm -rf $(LIBOQS_DIR)
	@rm -rf $(VENV_DIR)
	@rm -f $(LIBRARY_PATH)