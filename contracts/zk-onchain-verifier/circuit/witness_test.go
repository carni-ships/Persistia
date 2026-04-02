package circuit

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestWitness4Satisfies(t *testing.T) {
	w, err := LoadWitnessJSON("../testdata/dory_witness.json")
	if err != nil {
		t.Fatalf("failed to load witness JSON: %v", err)
	}

	assignment, err := w.AssignWitness4()
	if err != nil {
		t.Fatalf("failed to assign witness: %v", err)
	}

	var circuit DoryVerifier4Circuit
	t.Log("Compiling 4-round circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}
	t.Logf("4-round circuit compiled: %d constraints", cs.GetNbConstraints())

	wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness creation failed: %v", err)
	}

	t.Log("Checking satisfiability...")
	err = cs.IsSolved(wit)
	if err != nil {
		t.Fatalf("circuit not satisfied: %v", err)
	}
	t.Log("4-round Dory verifier circuit satisfied with real proof witness!")
}

func TestWitness11Satisfies(t *testing.T) {
	w, err := LoadWitnessJSON("../testdata/dory_witness_11.json")
	if err != nil {
		t.Fatalf("failed to load witness JSON: %v", err)
	}

	assignment, err := w.AssignWitness()
	if err != nil {
		t.Fatalf("failed to assign witness: %v", err)
	}

	var circuit DoryVerifierCircuit
	t.Log("Compiling 11-round circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}
	t.Logf("11-round circuit compiled: %d constraints", cs.GetNbConstraints())

	wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness creation failed: %v", err)
	}

	t.Log("Checking satisfiability...")
	err = cs.IsSolved(wit)
	if err != nil {
		t.Fatalf("circuit not satisfied: %v", err)
	}
	t.Log("11-round Dory verifier circuit satisfied with real proof witness!")
}

func Test11RoundCircuitCompiles(t *testing.T) {
	var circuit DoryVerifierCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}
	fmt.Printf("11-round circuit: %d constraints\n", cs.GetNbConstraints())
}

func Test4RoundCircuitCompiles(t *testing.T) {
	var circuit DoryVerifier4Circuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}
	fmt.Printf("4-round circuit: %d constraints\n", cs.GetNbConstraints())
}
