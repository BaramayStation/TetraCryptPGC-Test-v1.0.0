# Makefile for TetraCrypt setup

# Define variables
KYBER_REPO_URL = https://github.com/pq-crystals/kyber.git
KYBER_DIR = lib/kyber
LIBRARY_PATH = lib/libpqcrystals_kyber1024_ref.so

# Target: Setup environment
setup:
    @echo "Setting up the TetraCrypt environment..."
    @python3 -m venv venv
    @source venv/bin/activate && pip install -r requirements.txt
    @make kyber

# Target: Compile Kyber-1024
kyber:
    @echo "Compiling Kyber-1024..."
    @git clone $(KYBER_REPO_URL) $(KYBER_DIR)
    @cd $(KYBER_DIR)/ref && make
    @mv $(KYBER_DIR)/ref/lib/libpqcrystals_kyber1024_ref.so lib/

# Clean target: Cleanup compiled libraries
clean:
    @echo "Cleaning up..."
    @rm -rf $(KYBER_DIR)
    @rm -f $(LIBRARY_PATH)
