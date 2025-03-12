import seal  # Microsoft SEAL Library
import tenseal as ts

def encrypt_shared_secret(secret):
    """Encrypt shared secret using homomorphic encryption."""
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.generate_galois_keys()
    encrypted_secret = ts.ckks_vector(context, secret)
    return encrypted_secret
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
