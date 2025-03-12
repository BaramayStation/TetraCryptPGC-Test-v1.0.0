from qiskit import QuantumCircuit, Aer, transpile, assemble, execute
import random

def bb84_key_exchange(n=128):
    """Simulates a BB84 Quantum Key Distribution (QKD) session"""
    qc = QuantumCircuit(n, n)

    # Random Basis Selection
    alice_basis = [random.choice(["Z", "X"]) for _ in range(n)]
    alice_bits = [random.randint(0, 1) for _ in range(n)]

    # Encode in Quantum States
    for i in range(n):
        if alice_bits[i] == 1:
            qc.x(i)
        if alice_basis[i] == "X":
            qc.h(i)

    # Simulate Quantum Channel
    simulator = Aer.get_backend("qasm_simulator")
    result = execute(qc, simulator).result()
    raw_key = list(result.get_counts().keys())[0]

    # Key Reconciliation
    bob_basis = [random.choice(["Z", "X"]) for _ in range(n)]
    final_key = [alice_bits[i] for i in range(n) if alice_basis[i] == bob_basis[i]]

    return "".join(map(str, final_key))

if __name__ == "__main__":
    secure_key = bb84_key_exchange()
    print(f"Generated QKD Key: {secure_key}")
