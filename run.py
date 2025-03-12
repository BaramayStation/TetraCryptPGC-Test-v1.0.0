import sys
import os

# Ensure 'src/' is in the module search path
sys.path.append(os.path.abspath("src"))

# Import the main module (Modify as needed)
from src.hybrid_key_exchange import main

if __name__ == "__main__":
    main()
