package circuit

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type SolidityTestData struct {
	ProofA        [2]string `json:"proofA"`
	ProofB        [4]string `json:"proofB"`
	ProofC        [2]string `json:"proofC"`
	Commitments   [2]string `json:"commitments"`
	CommitmentPok [2]string `json:"commitmentPok"`
	InputHash     string    `json:"inputHash"`
}

// TestExportProofForFoundry generates a Groth16 proof, exports the gnark Solidity verifier,
// and writes both proof data and a Foundry test for end-to-end on-chain verification.
func TestExportProofForFoundry(t *testing.T) {
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

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("full witness: %v", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	t.Log("Generating Groth16 proof (with keccak256 hash for Solidity compatibility)...")
	proof, err := groth16.Prove(cs, pk, fullWitness,
		solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	t.Log("Verifying Groth16 proof (native)...")
	err = groth16.Verify(proof, vk, publicWitness,
		solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		t.Fatalf("native verify failed: %v", err)
	}
	t.Log("Native verification passed!")

	// Extract proof points
	bn254Proof := proof.(*groth16_bn254.Proof)
	var data SolidityTestData

	// A (G1)
	var ax, ay big.Int
	bn254Proof.Ar.X.BigInt(&ax)
	bn254Proof.Ar.Y.BigInt(&ay)
	data.ProofA = [2]string{"0x" + ax.Text(16), "0x" + ay.Text(16)}

	// B (G2) — EIP-197 order: (x1, x0, y1, y0)
	var bx0, bx1, by0, by1 big.Int
	bn254Proof.Bs.X.A0.BigInt(&bx0)
	bn254Proof.Bs.X.A1.BigInt(&bx1)
	bn254Proof.Bs.Y.A0.BigInt(&by0)
	bn254Proof.Bs.Y.A1.BigInt(&by1)
	data.ProofB = [4]string{
		"0x" + bx1.Text(16), "0x" + bx0.Text(16),
		"0x" + by1.Text(16), "0x" + by0.Text(16),
	}

	// C (G1)
	var cx, cy big.Int
	bn254Proof.Krs.X.BigInt(&cx)
	bn254Proof.Krs.Y.BigInt(&cy)
	data.ProofC = [2]string{"0x" + cx.Text(16), "0x" + cy.Text(16)}

	// Pedersen commitment (G1)
	if len(bn254Proof.Commitments) < 1 {
		t.Fatalf("expected at least 1 commitment, got %d", len(bn254Proof.Commitments))
	}
	var cmtX, cmtY big.Int
	bn254Proof.Commitments[0].X.BigInt(&cmtX)
	bn254Proof.Commitments[0].Y.BigInt(&cmtY)
	data.Commitments = [2]string{"0x" + cmtX.Text(16), "0x" + cmtY.Text(16)}
	t.Logf("Commitment: (%s, %s)", cmtX.String(), cmtY.String())

	// Commitment proof of knowledge (G1)
	var pokX, pokY big.Int
	bn254Proof.CommitmentPok.X.BigInt(&pokX)
	bn254Proof.CommitmentPok.Y.BigInt(&pokY)
	data.CommitmentPok = [2]string{"0x" + pokX.Text(16), "0x" + pokY.Text(16)}

	// Public input
	inputHash, ok := assignment.InputHash.(big.Int)
	if !ok {
		inputHashPtr, ok2 := assignment.InputHash.(*big.Int)
		if !ok2 {
			t.Fatalf("InputHash type: %T", assignment.InputHash)
		}
		inputHash = *inputHashPtr
	}
	data.InputHash = "0x" + inputHash.Text(16)

	// Export gnark Solidity verifier
	t.Log("Exporting Solidity verifier...")
	solFile := "../testdata/DoryVerifier11.sol"
	f, err := os.Create(solFile)
	if err != nil {
		t.Fatalf("create solidity file: %v", err)
	}
	err = vk.ExportSolidity(f)
	f.Close()
	if err != nil {
		t.Fatalf("export solidity: %v", err)
	}

	// Copy verifier to Foundry src
	solBytes, _ := os.ReadFile(solFile)
	os.WriteFile("../foundry-test/src/DoryVerifier11.sol", solBytes, 0644)

	// Generate Foundry test
	foundryTest := generateFoundryTest(&data)
	os.WriteFile("../foundry-test/test/DoryVerifierTest.t.sol", []byte(foundryTest), 0644)

	// Write proof data JSON
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile("../testdata/proof_data.json", jsonBytes, 0644)

	t.Logf("InputHash: %s", data.InputHash)
	t.Log("All artifacts exported successfully!")
}

func generateFoundryTest(data *SolidityTestData) string {
	pad := func(s string) string {
		if len(s) < 66 {
			return "0x" + strings.Repeat("0", 66-len(s)) + s[2:]
		}
		return s
	}

	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DoryVerifier11.sol";

contract DoryVerifierTest is Test {
    Verifier verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_verifyProof_realProof() public view {
        uint256[8] memory proof;
        proof[0] = %s;
        proof[1] = %s;
        proof[2] = %s;
        proof[3] = %s;
        proof[4] = %s;
        proof[5] = %s;
        proof[6] = %s;
        proof[7] = %s;

        uint256[2] memory commitments;
        commitments[0] = %s;
        commitments[1] = %s;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = %s;
        commitmentPok[1] = %s;

        uint256[1] memory input;
        input[0] = %s;

        verifier.verifyProof(proof, commitments, commitmentPok, input);
    }

    function test_verifyProof_wrongInput_reverts() public {
        uint256[8] memory proof;
        proof[0] = %s;
        proof[1] = %s;
        proof[2] = %s;
        proof[3] = %s;
        proof[4] = %s;
        proof[5] = %s;
        proof[6] = %s;
        proof[7] = %s;

        uint256[2] memory commitments;
        commitments[0] = %s;
        commitments[1] = %s;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = %s;
        commitmentPok[1] = %s;

        uint256[1] memory input;
        input[0] = %s + 1;

        vm.expectRevert();
        verifier.verifyProof(proof, commitments, commitmentPok, input);
    }

    function test_verifyProof_gasUsage() public {
        uint256[8] memory proof;
        proof[0] = %s;
        proof[1] = %s;
        proof[2] = %s;
        proof[3] = %s;
        proof[4] = %s;
        proof[5] = %s;
        proof[6] = %s;
        proof[7] = %s;

        uint256[2] memory commitments;
        commitments[0] = %s;
        commitments[1] = %s;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = %s;
        commitmentPok[1] = %s;

        uint256[1] memory input;
        input[0] = %s;

        uint256 gasBefore = gasleft();
        verifier.verifyProof(proof, commitments, commitmentPok, input);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("Gas used for verifyProof", gasUsed);
    }
}
`,
		// test 1
		pad(data.ProofA[0]), pad(data.ProofA[1]),
		pad(data.ProofB[0]), pad(data.ProofB[1]), pad(data.ProofB[2]), pad(data.ProofB[3]),
		pad(data.ProofC[0]), pad(data.ProofC[1]),
		pad(data.Commitments[0]), pad(data.Commitments[1]),
		pad(data.CommitmentPok[0]), pad(data.CommitmentPok[1]),
		pad(data.InputHash),
		// test 2
		pad(data.ProofA[0]), pad(data.ProofA[1]),
		pad(data.ProofB[0]), pad(data.ProofB[1]), pad(data.ProofB[2]), pad(data.ProofB[3]),
		pad(data.ProofC[0]), pad(data.ProofC[1]),
		pad(data.Commitments[0]), pad(data.Commitments[1]),
		pad(data.CommitmentPok[0]), pad(data.CommitmentPok[1]),
		pad(data.InputHash),
		// test 3
		pad(data.ProofA[0]), pad(data.ProofA[1]),
		pad(data.ProofB[0]), pad(data.ProofB[1]), pad(data.ProofB[2]), pad(data.ProofB[3]),
		pad(data.ProofC[0]), pad(data.ProofC[1]),
		pad(data.Commitments[0]), pad(data.Commitments[1]),
		pad(data.CommitmentPok[0]), pad(data.CommitmentPok[1]),
		pad(data.InputHash),
	)
}
