from secrets import token_bytes
from functools import reduce
import operator

def generate_mpc_key_shares(secret, num_shares, threshold):
    """Generate secret shares using Shamir's Secret Sharing (MPC)."""
    if threshold > num_shares:
        raise ValueError("Threshold cannot be greater than number of shares")

    coefficients = [secret] + [token_bytes(len(secret)) for _ in range(threshold - 1)]
    shares = []

    for i in range(1, num_shares + 1):
        share = sum(coeff * i**idx for idx, coeff in enumerate(coefficients))
        shares.append((i, share.to_bytes(len(secret), "big")))

    return shares

def reconstruct_secret(shares):
    """Reconstruct the original secret from a threshold of shares."""
    def lagrange_interpolate(x, points):
        """Perform Lagrange interpolation to reconstruct the secret."""
        sum_result = 0
        for i, (xi, yi) in enumerate(points):
            term = yi
            for j, (xj, _) in enumerate(points):
                if i != j:
                    term *= (x - xj) * pow(xi - xj, -1, 256)
            sum_result += term
        return sum_result.to_bytes(len(points[0][1]), "big")

    return lagrange_interpolate(0, shares)
