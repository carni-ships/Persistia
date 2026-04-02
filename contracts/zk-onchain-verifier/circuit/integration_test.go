package circuit

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// IntegrationData captures all data needed for on-chain verification.
type IntegrationData struct {
	// Groth16 proof elements (hex-encoded)
	ProofAr  [2]string `json:"proof_ar"`
	ProofBs  [4]string `json:"proof_bs"`
	ProofKrs [2]string `json:"proof_krs"`

	// Public inputs (as raw uint256 hex values)
	PublicInputs []string `json:"public_inputs"`

	// Circuit metadata
	NumConstraints int `json:"num_constraints"`
	NumPublicInputs int `json:"num_public_inputs"`
}

func TestIntegrationExport(t *testing.T) {
	w, err := LoadWitnessJSON("../testdata/dory_witness.json")
	if err != nil {
		t.Fatalf("load witness: %v", err)
	}

	assignment, err := w.AssignWitness4()
	if err != nil {
		t.Fatalf("assign witness: %v", err)
	}

	// Compile
	var circuit DoryVerifier4Circuit
	t.Log("Compiling circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Compiled: %d constraints", cs.GetNbConstraints())

	// Setup
	t.Log("Groth16 setup...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Witness
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	// Prove
	t.Log("Proving...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// Verify
	t.Log("Verifying...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("Groth16 verification PASSED!")

	// Export verification key
	vkFile := "../testdata/vk.bin"
	f, err := os.Create(vkFile)
	if err != nil {
		t.Fatalf("create vk file: %v", err)
	}
	_, err = vk.WriteTo(f)
	f.Close()
	if err != nil {
		t.Fatalf("write vk: %v", err)
	}

	// Export proof
	proofFile := "../testdata/proof.bin"
	f, err = os.Create(proofFile)
	if err != nil {
		t.Fatalf("create proof file: %v", err)
	}
	_, err = proof.WriteTo(f)
	f.Close()
	if err != nil {
		t.Fatalf("write proof: %v", err)
	}

	// Export public witness
	pubWitFile := "../testdata/public_witness.bin"
	f, err = os.Create(pubWitFile)
	if err != nil {
		t.Fatalf("create pub witness file: %v", err)
	}
	_, err = publicWitness.WriteTo(f)
	f.Close()
	if err != nil {
		t.Fatalf("write pub witness: %v", err)
	}

	// Export Solidity verifier
	solFile := "../testdata/DoryVerifier.sol"
	f, err = os.Create(solFile)
	if err != nil {
		t.Fatalf("create sol file: %v", err)
	}
	err = vk.ExportSolidity(f)
	f.Close()
	if err != nil {
		t.Fatalf("export solidity: %v", err)
	}

	// Export integration data as JSON
	schema, err := frontend.NewSchema(ecc.BN254.ScalarField(), &circuit)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	pubJSON, err := publicWitness.ToJSON(schema)
	if err != nil {
		t.Fatalf("pub witness to json: %v", err)
	}

	jsonFile := "../testdata/integration_data.json"
	err = os.WriteFile(jsonFile, pubJSON, 0644)
	if err != nil {
		t.Fatalf("write integration json: %v", err)
	}

	t.Logf("Exported: vk.bin, proof.bin, public_witness.bin, DoryVerifier.sol, integration_data.json")
	t.Logf("Public witness JSON:\n%s", string(pubJSON[:min(len(pubJSON), 500)]))
}
