
import pqcrypto.key.falcon as falcon
import hashlib

def generate_key():
    public_key, private_key = falcon.generate_keypair()
    return public_key.hex(), private_key.hex()

def sign_message(message, private_key_hex):
    private_key = falcon.SecretKey(bytes.fromhex(private_key_hex))
    message_hash = hashlib.sha3_512(message.encode()).digest()
    signature = falcon.sign(message_hash, private_key)
    return signature.hex()

def verify_signature(message, signature_hex, public_key_hex):
    public_key = falcon.PublicKey(bytes.fromhex(public_key_hex))
    message_hash = hashlib.sha3_512(message.encode()).digest()
    try:
        falcon.verify(message_hash, bytes.fromhex(signature_hex), public_key)
        return True
    except:
        return False

def run_benchmarks():
    import time
    start = time.time()
    for _ in range(100):
        public_key, private_key = generate_key()
        sign_message("Benchmark Test", private_key)
    end = time.time()
    print(f"Benchmark completed in {end - start:.4f} seconds")
