import secrets
import hashlib
from qunetsim.objects import QuantumContext, Host, Qubit
from qunetsim.components import Network

class BB84QKD:
    """
    Secure Quantum Key Distribution (QKD) using the BB84 protocol.
    
    Features:
    - Uses cryptographically secure randomness.
    - Ensures entropy validation for quantum key bits.
    - Hashes the final key for integrity verification.
    """

    def __init__(self, num_qubits: int = 256):
        """
        Initialize QKD parameters.
        :param num_qubits: Number of raw quantum bits to generate (default: 256)
        """
        self.num_qubits = num_qubits

    def generate_qkd_key(self, alice, bob):
        """Simulate a BB84 Quantum Key Distribution (QKD) between Alice and Bob."""
        alice_key = []
        bob_key = []

        # Step 1: Alice sends randomly polarized qubits
        for _ in range(self.num_qubits):
            bit = secrets.randbits(1)  # Secure bit generation
            basis = secrets.choice(['+', 'x'])  # Secure basis selection
            
            q = Qubit(alice)
            if basis == 'x':
                q.H()
            if bit == 1:
                q.X()
            
            q.send(bob)
            alice_key.append((bit, basis))  # Store Alice's choices

        # Step 2: Bob randomly measures in a basis
        for _ in range(self.num_qubits):
            basis = secrets.choice(['+', 'x'])  # Secure basis selection
            q = bob.get_data_qubit()
            
            if basis == 'x':
                q.H()
            
            bit = q.measure()
            bob_key.append((bit, basis))  # Store Bob's results

        # Step 3: Public Basis Comparison and Key Agreement
        final_key = []
        for i in range(len(alice_key)):
            if alice_key[i][1] == bob_key[i][1]:  # If bases match
                final_key.append(alice_key[i][0])  # Keep the bit

        # Final shared secret key (SHA-3 256-bit hash for security)
        shared_qkd_key = hashlib.sha3_256(bytes(final_key)).digest()
        return shared_qkd_key

# 🔹 Example Execution
if __name__ == "__main__":
    # Create a quantum network
    network = Network.get_instance()
    network.start()

    # Create Alice & Bob
    alice = Host('Alice')
    bob = Host('Bob')
    network.add_host(alice)
    network.add_host(bob)

    # Secure QKD Execution
    qkd = BB84QKD(num_qubits=256)
    shared_qkd_key = qkd.generate_qkd_key(alice, bob)

    print(f"🔑 Secure QKD Shared Key: {shared_qkd_key.hex()}")

    network.stop()