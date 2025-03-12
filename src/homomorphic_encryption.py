import seal  # Microsoft SEAL Library
import tenseal as ts

def setup_homomorphic_context():
    """Initialize SEAL and TenSEAL homomorphic encryption contexts."""
    # SEAL Context (BFV)
    seal_context = seal.SEALContext(seal.EncryptionParameters(seal.SCHEME_TYPE.BFV))
    keygen = seal.KeyGenerator(seal_context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    encryptor = seal.Encryptor(seal_context, public_key)
    evaluator = seal.Evaluator(seal_context)
    decryptor = seal.Decryptor(seal_context, secret_key)

    # TenSEAL Context (CKKS)
    tenseal_context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    tenseal_context.generate_galois_keys()

    return encryptor, evaluator, decryptor, tenseal_context

def encrypt_shared_secret(secret):
    """Encrypt shared secret using homomorphic encryption (CKKS via TenSEAL)."""
    _, _, _, tenseal_context = setup_homomorphic_context()
    encrypted_secret = ts.ckks_vector(tenseal_context, secret)
    return encrypted_secret

def encrypt_value(value: int):
    """Encrypt a numerical value using homomorphic encryption (BFV via SEAL)."""
    encryptor, _, _, _ = setup_homomorphic_context()
    plain = seal.Plaintext(str(value))
    encrypted = seal.Ciphertext()
    encryptor.encrypt(plain, encrypted)
    return encrypted.save()

def compute_secure_sum(enc_value1, enc_value2):
    """Perform homomorphic addition on encrypted values using SEAL."""
    _, evaluator, _, _ = setup_homomorphic_context()
    enc_result = seal.Ciphertext()
    evaluator.add(enc_value1, enc_value2, enc_result)
    return enc_result.save()

def decrypt_value(enc_value):
    """Decrypt an encrypted value using SEAL."""
    _, _, decryptor, _ = setup_homomorphic_context()
    decrypted = seal.Plaintext()
    decryptor.decrypt(enc_value, decrypted)
    return int(decrypted.to_string())

# Example Execution
if __name__ == "__main__":
    print("\n🔐 Initializing Homomorphic Encryption...\n")

    # Encrypt & Compute Secure Sum
    num1 = 42
    num2 = 58

    print(f"🔒 Encrypting Values: {num1}, {num2}")
    encrypted_num1 = encrypt_value(num1)
    encrypted_num2 = encrypt_value(num2)

    print("➕ Computing Secure Sum Homomorphically...")
    encrypted_sum = compute_secure_sum(encrypted_num1, encrypted_num2)

    print("🔓 Decrypting Secure Sum...")
    decrypted_sum = decrypt_value(encrypted_sum)

    print(f"\n✅ Homomorphic Secure Computation Result: {decrypted_sum}")
