import seal  # Microsoft SEAL Library

def encrypt_value(value: int, encryptor) -> str:
    """Encrypt a numerical value using homomorphic encryption."""
    plain = seal.Plaintext(str(value))
    encrypted = seal.Ciphertext()
    encryptor.encrypt(plain, encrypted)
    return encrypted.save()

def compute_secure_sum(enc_value1, enc_value2, evaluator) -> str:
    """Perform homomorphic addition on encrypted values."""
    enc_result = seal.Ciphertext()
    evaluator.add(enc_value1, enc_value2, enc_result)
    return enc_result.save()
