import seal  # Microsoft SEAL Library
import tenseal as ts
import logging

# 🔹 Secure Logging for Homomorphic Encryption (HE)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def setup_homomorphic_context():
    """Initialize SEAL and TenSEAL homomorphic encryption contexts securely."""
    try:
        logging.info("🔹 Initializing SEAL (BFV) Encryption Context...")
        seal_context = seal.SEALContext(seal.EncryptionParameters(seal.SCHEME_TYPE.BFV))
        keygen = seal.KeyGenerator(seal_context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        encryptor = seal.Encryptor(seal_context, public_key)
        evaluator = seal.Evaluator(seal_context)
        decryptor = seal.Decryptor(seal_context, secret_key)

        logging.info("✅ SEAL Homomorphic Context Ready.")

        logging.info("🔹 Initializing TenSEAL (CKKS) Encryption Context...")
        tenseal_context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=8192,
            coeff_mod_bit_sizes=[60, 40, 40, 60]
        )
        tenseal_context.generate_galois_keys()
        logging.info("✅ TenSEAL Homomorphic Context Ready.")

        return encryptor, evaluator, decryptor, tenseal_context

    except Exception as e:
        logging.error(f"⚠️ Homomorphic Encryption Initialization Failed: {e}")
        raise RuntimeError("Failed to initialize homomorphic encryption")


def encrypt_shared_secret(secret):
    """Encrypt a shared secret using CKKS Homomorphic Encryption (TenSEAL)."""
    try:
        _, _, _, tenseal_context = setup_homomorphic_context()
        encrypted_secret = ts.ckks_vector(tenseal_context, secret)
        logging.info("✅ Shared Secret Encrypted Securely.")
        return encrypted_secret
    except Exception as e:
        logging.error(f"⚠️ Shared Secret Encryption Failed: {e}")
        raise RuntimeError("Homomorphic Encryption Failed")


def encrypt_value(value: int):
    """Encrypt an integer value using BFV Homomorphic Encryption (Microsoft SEAL)."""
    try:
        encryptor, _, _, _ = setup_homomorphic_context()
        plain = seal.Plaintext(str(value))
        encrypted = seal.Ciphertext()
        encryptor.encrypt(plain, encrypted)
        logging.info(f"✅ Encrypted Integer Value: {value}")
        return encrypted.save()
    except Exception as e:
        logging.error(f"⚠️ Encryption of Value {value} Failed: {e}")
        raise RuntimeError("Failed to encrypt value")


def compute_secure_sum(enc_value1, enc_value2):
    """Perform homomorphic addition on encrypted values using SEAL."""
    try:
        _, evaluator, _, _ = setup_homomorphic_context()
        enc_result = seal.Ciphertext()
        evaluator.add(enc_value1, enc_value2, enc_result)
        logging.info("✅ Secure Homomorphic Addition Computed.")
        return enc_result.save()
    except Exception as e:
        logging.error(f"⚠️ Secure Addition Failed: {e}")
        raise RuntimeError("Homomorphic addition failed")


def decrypt_value(enc_value):
    """Decrypt an encrypted value using SEAL."""
    try:
        _, _, decryptor, _ = setup_homomorphic_context()
        decrypted = seal.Plaintext()
        decryptor.decrypt(enc_value, decrypted)
        logging.info(f"✅ Decrypted Value: {int(decrypted.to_string())}")
        return int(decrypted.to_string())
    except Exception as e:
        logging.error(f"⚠️ Decryption Failed: {e}")
        raise RuntimeError("Failed to decrypt value")


# 🔹 Example Execution for Future-Proofed Homomorphic Computation
if __name__ == "__main__":
    logging.info("\n🔐 Initializing Future-Proofed Homomorphic Encryption...\n")

    # Encrypt & Compute Secure Sum
    num1 = 42
    num2 = 58

    logging.info(f"🔒 Encrypting Values: {num1}, {num2}")
    encrypted_num1 = encrypt_value(num1)
    encrypted_num2 = encrypt_value(num2)

    logging.info("➕ Computing Secure Sum Homomorphically...")
    encrypted_sum = compute_secure_sum(encrypted_num1, encrypted_num2)

    logging.info("🔓 Decrypting Secure Sum...")
    decrypted_sum = decrypt_value(encrypted_sum)

    logging.info(f"\n✅ Homomorphic Secure Computation Result: {decrypted_sum}")