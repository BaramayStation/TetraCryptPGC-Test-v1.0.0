import tenseal as ts

def encrypt_shared_secret(secret):
    """Encrypt shared secret using homomorphic encryption."""
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.generate_galois_keys()
    encrypted_secret = ts.ckks_vector(context, secret)
    return encrypted_secret
