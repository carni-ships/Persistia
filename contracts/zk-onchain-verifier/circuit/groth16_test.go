package circuit

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestGroth16ProveVerify11(t *testing.T) {
	w, err := LoadWitnessJSON("../testdata/dory_witness_11.json")
	if err != nil {
		t.Fatalf("load witness: %v", err)
	}

	assignment, err := w.AssignWitness()
	if err != nil {
		t.Fatalf("assign witness: %v", err)
	}

	var circuit DoryVerifierCircuit
	t.Log("Compiling 11-round circuit to R1CS...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Circuit compiled: %d constraints", cs.GetNbConstraints())

	t.Log("Running Groth16 setup...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Log("Setup complete")

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("full witness: %v", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	t.Log("Generating Groth16 proof...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	t.Log("Proof generated")

	t.Log("Verifying Groth16 proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("Groth16 proof verified!")

	solFile := "../testdata/DoryVerifier11.sol"
	f, err := os.Create(solFile)
	if err != nil {
		t.Fatalf("create solidity file: %v", err)
	}
	defer f.Close()

	t.Log("Exporting Solidity verifier...")
	err = vk.ExportSolidity(f)
	if err != nil {
		t.Fatalf("export solidity: %v", err)
	}
	t.Logf("Solidity verifier exported to %s", solFile)
}

func TestGroth16ProveVerify(t *testing.T) {
	w, err := LoadWitnessJSON("../testdata/dory_witness.json")
	if err != nil {
		t.Fatalf("load witness: %v", err)
	}

	assignment, err := w.AssignWitness4()
	if err != nil {
		t.Fatalf("assign witness: %v", err)
	}

	// Step 1: Compile
	var circuit DoryVerifier4Circuit
	t.Log("Compiling circuit to R1CS...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Circuit compiled: %d constraints", cs.GetNbConstraints())

	// Step 2: Groth16 setup (trusted setup)
	t.Log("Running Groth16 setup...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Log("Setup complete")

	// Step 3: Create witness
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("full witness: %v", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	// Step 4: Prove
	t.Log("Generating Groth16 proof...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	t.Log("Proof generated")

	// Step 5: Verify
	t.Log("Verifying Groth16 proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("Groth16 proof verified!")

	// Step 6: Export Solidity verifier
	solFile := "../testdata/DoryVerifier.sol"
	f, err := os.Create(solFile)
	if err != nil {
		t.Fatalf("create solidity file: %v", err)
	}
	defer f.Close()

	t.Log("Exporting Solidity verifier...")
	err = vk.ExportSolidity(f)
	if err != nil {
		t.Fatalf("export solidity: %v", err)
	}
	t.Logf("Solidity verifier exported to %s", solFile)
}
