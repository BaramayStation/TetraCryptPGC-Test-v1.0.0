class TetraError(Exception):
    pass

# Example: In handshake verification
if not valid_signature:  # Replace with your actual condition
    raise TetraError("Invalid handshake data")
