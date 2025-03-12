import random
from qunetsim.objects import QuantumContext, Host, Qubit
from qunetsim.components import Network
import hashlib

def bb84_qkd(alice, bob):
    """
    Simulate a BB84 Quantum Key Distribution (QKD) between Alice and Bob.
    """

    alice_key = []
    bob_key = []
    
    # Step 1: Alice sends randomly polarized qubits
    for _ in range(256):  # Generate 256 raw bits
        bit = random.randint(0, 1)
        basis = random.choice(['+', 'x'])  # Choose a random basis
        
        q = Qubit(alice)
        if basis == 'x':
            q.H()
        if bit == 1:
            q.X()
        
        q.send(bob)

    # Step 2: Bob randomly measures in a basis
    for _ in range(256):
        basis = random.choice(['+', 'x'])
        q = bob.get_data_qubit()
        
        if basis == 'x':
            q.H()
        
        bit = q.measure()
        bob_key.append(bit)

    # Step 3: Public basis comparison
    for i in range(len(alice_key)):
        if alice_key[i][1] == bob_key[i][1]:  # If bases match
            bob_key.append(alice_key[i][0])  # Keep the bit

    # Final shared key
    shared_qkd_key = hashlib.sha3_256(bytes(bob_key)).digest()  # 256-bit key
    return shared_qkd_key

if __name__ == "__main__":
    # Create a quantum network
    network = Network.get_instance()
    network.start()

    # Create Alice & Bob
    alice = Host('Alice')
    bob = Host('Bob')
    network.add_host(alice)
    network.add_host(bob)

    # Execute QKD
    shared_qkd_key = bb84_qkd(alice, bob)
    print(f"QKD Shared Key: {shared_qkd_key.hex()}")

    network.stop()
