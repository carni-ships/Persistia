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
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// TestJoltPipelineWitnessSatisfies loads the Dory witness from jolt_onchain_proof.json
// and checks that it satisfies the 7-round circuit constraints.
func TestJoltPipelineWitnessSatisfies(t *testing.T) {
	w, err := LoadJoltExportWitness("../foundry-test/testdata/jolt_onchain_proof.json")
	if err != nil {
		t.Fatalf("load jolt export witness: %v", err)
	}
	t.Logf("Loaded Dory witness: %d rounds", w.NumRounds)

	assignment, err := w.AssignWitness7()
	if err != nil {
		t.Fatalf("assign witness: %v", err)
	}

	var circuit DoryVerifier7Circuit
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("circuit not satisfied: %v", err)
	}
	t.Log("7-round circuit satisfied with Jolt export witness!")
}

// TestJoltPipelineGroth16 is the full end-to-end pipeline:
// jolt_onchain_proof.json -> Dory witness -> 7-round circuit -> Groth16 proof -> Solidity artifacts
func TestJoltPipelineGroth16(t *testing.T) {
	w, err := LoadJoltExportWitness("../foundry-test/testdata/jolt_onchain_proof.json")
	if err != nil {
		t.Fatalf("load jolt export witness: %v", err)
	}
	t.Logf("Loaded Dory witness: %d rounds", w.NumRounds)

	assignment, err := w.AssignWitness7()
	if err != nil {
		t.Fatalf("assign witness: %v", err)
	}

	var circuit DoryVerifier7Circuit
	t.Log("Compiling 7-round circuit to R1CS...")
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

	t.Log("Generating Groth16 proof...")
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
	t.Log("Native Groth16 verification passed!")

	// Extract proof points for Solidity
	bn254Proof := proof.(*groth16_bn254.Proof)
	var data SolidityTestData

	var ax, ay big.Int
	bn254Proof.Ar.X.BigInt(&ax)
	bn254Proof.Ar.Y.BigInt(&ay)
	data.ProofA = [2]string{"0x" + ax.Text(16), "0x" + ay.Text(16)}

	var bx0, bx1, by0, by1 big.Int
	bn254Proof.Bs.X.A0.BigInt(&bx0)
	bn254Proof.Bs.X.A1.BigInt(&bx1)
	bn254Proof.Bs.Y.A0.BigInt(&by0)
	bn254Proof.Bs.Y.A1.BigInt(&by1)
	data.ProofB = [4]string{
		"0x" + bx1.Text(16), "0x" + bx0.Text(16),
		"0x" + by1.Text(16), "0x" + by0.Text(16),
	}

	var cx, cy big.Int
	bn254Proof.Krs.X.BigInt(&cx)
	bn254Proof.Krs.Y.BigInt(&cy)
	data.ProofC = [2]string{"0x" + cx.Text(16), "0x" + cy.Text(16)}

	if len(bn254Proof.Commitments) < 1 {
		t.Fatalf("expected at least 1 commitment, got %d", len(bn254Proof.Commitments))
	}
	var cmtX, cmtY big.Int
	bn254Proof.Commitments[0].X.BigInt(&cmtX)
	bn254Proof.Commitments[0].Y.BigInt(&cmtY)
	data.Commitments = [2]string{"0x" + cmtX.Text(16), "0x" + cmtY.Text(16)}

	var pokX, pokY big.Int
	bn254Proof.CommitmentPok.X.BigInt(&pokX)
	bn254Proof.CommitmentPok.Y.BigInt(&pokY)
	data.CommitmentPok = [2]string{"0x" + pokX.Text(16), "0x" + pokY.Text(16)}

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
	solFile := "../testdata/DoryVerifier7.sol"
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
	os.WriteFile("../foundry-test/src/DoryVerifier7.sol", solBytes, 0644)

	// Write proof data JSON for Foundry integration
	proofJSON := map[string]interface{}{
		"proofA":        data.ProofA,
		"proofB":        data.ProofB,
		"proofC":        data.ProofC,
		"commitments":   data.Commitments,
		"commitmentPok": data.CommitmentPok,
		"inputHash":     data.InputHash,
	}
	jsonBytes, _ := json.MarshalIndent(proofJSON, "", "  ")
	os.WriteFile("../testdata/jolt_groth16_proof.json", jsonBytes, 0644)
	os.WriteFile("../foundry-test/testdata/jolt_groth16_proof.json", jsonBytes, 0644)

	// Generate standalone DoryVerifier7 Foundry test
	foundryTest := generateDoryVerifier7Test(&data)
	os.WriteFile("../foundry-test/test/DoryVerifier7Test.t.sol", []byte(foundryTest), 0644)

	t.Logf("InputHash: %s", data.InputHash)
	t.Logf("ProofA: [%s, %s]", data.ProofA[0], data.ProofA[1])
	t.Log("All Jolt pipeline artifacts exported successfully!")
}

// TestJoltPipelineSha3Satisfies loads the sha3 production Dory witness
// and checks that it satisfies the 9-round circuit constraints.
func TestJoltPipelineSha3Satisfies(t *testing.T) {
	w, err := LoadJoltExportWitness("../foundry-test/testdata/jolt_onchain_proof_sha3.json")
	if err != nil {
		t.Fatalf("load jolt export witness: %v", err)
	}
	t.Logf("Loaded Dory witness: %d rounds", w.NumRounds)

	assignment, err := w.AssignWitness9()
	if err != nil {
		t.Fatalf("assign witness: %v", err)
	}

	var circuit DoryVerifier9Circuit
	err = test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("circuit not satisfied: %v", err)
	}
	t.Log("9-round circuit satisfied with sha3 production witness!")
}

// TestJoltPipelineSha3Groth16 is the full production pipeline:
// jolt_onchain_proof_sha3.json -> 9-round circuit -> Groth16 proof -> Solidity artifacts
func TestJoltPipelineSha3Groth16(t *testing.T) {
	w, err := LoadJoltExportWitness("../foundry-test/testdata/jolt_onchain_proof_sha3.json")
	if err != nil {
		t.Fatalf("load jolt export witness: %v", err)
	}
	t.Logf("Loaded Dory witness: %d rounds", w.NumRounds)

	assignment, err := w.AssignWitness9()
	if err != nil {
		t.Fatalf("assign witness: %v", err)
	}

	var circuit DoryVerifier9Circuit
	t.Log("Compiling 9-round circuit to R1CS...")
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

	t.Log("Generating Groth16 proof...")
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
	t.Log("Native Groth16 verification passed!")

	bn254Proof := proof.(*groth16_bn254.Proof)
	var data SolidityTestData

	var ax, ay big.Int
	bn254Proof.Ar.X.BigInt(&ax)
	bn254Proof.Ar.Y.BigInt(&ay)
	data.ProofA = [2]string{"0x" + ax.Text(16), "0x" + ay.Text(16)}

	var bx0, bx1, by0, by1 big.Int
	bn254Proof.Bs.X.A0.BigInt(&bx0)
	bn254Proof.Bs.X.A1.BigInt(&bx1)
	bn254Proof.Bs.Y.A0.BigInt(&by0)
	bn254Proof.Bs.Y.A1.BigInt(&by1)
	data.ProofB = [4]string{
		"0x" + bx1.Text(16), "0x" + bx0.Text(16),
		"0x" + by1.Text(16), "0x" + by0.Text(16),
	}

	var cx, cy big.Int
	bn254Proof.Krs.X.BigInt(&cx)
	bn254Proof.Krs.Y.BigInt(&cy)
	data.ProofC = [2]string{"0x" + cx.Text(16), "0x" + cy.Text(16)}

	if len(bn254Proof.Commitments) < 1 {
		t.Fatalf("expected at least 1 commitment, got %d", len(bn254Proof.Commitments))
	}
	var cmtX, cmtY big.Int
	bn254Proof.Commitments[0].X.BigInt(&cmtX)
	bn254Proof.Commitments[0].Y.BigInt(&cmtY)
	data.Commitments = [2]string{"0x" + cmtX.Text(16), "0x" + cmtY.Text(16)}

	var pokX, pokY big.Int
	bn254Proof.CommitmentPok.X.BigInt(&pokX)
	bn254Proof.CommitmentPok.Y.BigInt(&pokY)
	data.CommitmentPok = [2]string{"0x" + pokX.Text(16), "0x" + pokY.Text(16)}

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
	solFile := "../testdata/DoryVerifier9.sol"
	f, err := os.Create(solFile)
	if err != nil {
		t.Fatalf("create solidity file: %v", err)
	}
	err = vk.ExportSolidity(f)
	f.Close()
	if err != nil {
		t.Fatalf("export solidity: %v", err)
	}

	solBytes, _ := os.ReadFile(solFile)
	os.WriteFile("../foundry-test/src/DoryVerifier9.sol", solBytes, 0644)

	proofJSON := map[string]interface{}{
		"proofA":        data.ProofA,
		"proofB":        data.ProofB,
		"proofC":        data.ProofC,
		"commitments":   data.Commitments,
		"commitmentPok": data.CommitmentPok,
		"inputHash":     data.InputHash,
	}
	jsonBytes, _ := json.MarshalIndent(proofJSON, "", "  ")
	os.WriteFile("../testdata/jolt_groth16_proof_sha3.json", jsonBytes, 0644)
	os.WriteFile("../foundry-test/testdata/jolt_groth16_proof_sha3.json", jsonBytes, 0644)

	foundryTest := generateDoryVerifier9Test(&data)
	os.WriteFile("../foundry-test/test/DoryVerifier9Test.t.sol", []byte(foundryTest), 0644)

	t.Logf("InputHash: %s", data.InputHash)
	t.Log("All sha3 production pipeline artifacts exported successfully!")
}

func generateDoryVerifier9Test(data *SolidityTestData) string {
	pad := func(s string) string {
		if len(s) < 66 {
			return "0x" + strings.Repeat("0", 66-len(s)) + s[2:]
		}
		return s
	}

	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DoryVerifier9.sol";

contract DoryVerifier9Test is Test {
    Verifier verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_verifyProof_sha3Production() public view {
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
}
`,
		pad(data.ProofA[0]), pad(data.ProofA[1]),
		pad(data.ProofB[0]), pad(data.ProofB[1]), pad(data.ProofB[2]), pad(data.ProofB[3]),
		pad(data.ProofC[0]), pad(data.ProofC[1]),
		pad(data.Commitments[0]), pad(data.Commitments[1]),
		pad(data.CommitmentPok[0]), pad(data.CommitmentPok[1]),
		pad(data.InputHash),
	)
}

func generateDoryVerifier7Test(data *SolidityTestData) string {
	pad := func(s string) string {
		if len(s) < 66 {
			return "0x" + strings.Repeat("0", 66-len(s)) + s[2:]
		}
		return s
	}

	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DoryVerifier7.sol";

contract DoryVerifier7Test is Test {
    Verifier verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_verifyProof_joltExport() public view {
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
}
`,
		pad(data.ProofA[0]), pad(data.ProofA[1]),
		pad(data.ProofB[0]), pad(data.ProofB[1]), pad(data.ProofB[2]), pad(data.ProofB[3]),
		pad(data.ProofC[0]), pad(data.ProofC[1]),
		pad(data.Commitments[0]), pad(data.Commitments[1]),
		pad(data.CommitmentPok[0]), pad(data.CommitmentPok[1]),
		pad(data.InputHash),
	)
}
