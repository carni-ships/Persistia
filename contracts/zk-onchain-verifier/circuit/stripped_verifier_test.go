package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"golang.org/x/crypto/sha3"
)

// TestStrippedVerifierConstant verifies that the precomputed folded constant
// (CONSTANT + PUB_1 * keccak256(commitment=(0,0)) % R) matches what the
// original gnark-generated verifier would compute.
func TestStrippedVerifierConstant(t *testing.T) {
	R := new(big.Int)
	R.SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)

	// Compute COMMITMENT_HASH = keccak256(abi.encodePacked(uint256(0), uint256(0))) % R
	data := make([]byte, 64)
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	hashBytes := h.Sum(nil)
	commitHash := new(big.Int).SetBytes(hashBytes)
	commitHash.Mod(commitHash, R)

	t.Logf("COMMITMENT_HASH = 0x%064x", commitHash)

	// Original points from gnark-generated verifier
	constantX := new(big.Int)
	constantX.SetString("14741357090615952705974562728907902077863377647558084683092194948301308606092", 10)
	constantY := new(big.Int)
	constantY.SetString("11342823257098206432375158847157736037487810098746534093866200119098641598642", 10)

	pub1X := new(big.Int)
	pub1X.SetString("10999668286908204714826795852744673690808083441369311345171428048726755847673", 10)
	pub1Y := new(big.Int)
	pub1Y.SetString("11057105331021896936850508040265921063426184228779362078271433123185532169527", 10)

	// Compute: CONSTANT + PUB_1 * COMMITMENT_HASH
	var constantPt, pub1Pt, scaledPub1, newConstant bn254.G1Affine
	constantPt.X.SetBigInt(constantX)
	constantPt.Y.SetBigInt(constantY)
	pub1Pt.X.SetBigInt(pub1X)
	pub1Pt.Y.SetBigInt(pub1Y)

	scaledPub1.ScalarMultiplication(&pub1Pt, commitHash)

	var cJac, sJac bn254.G1Jac
	cJac.FromAffine(&constantPt)
	sJac.FromAffine(&scaledPub1)
	cJac.AddAssign(&sJac)
	newConstant.FromJacobian(&cJac)

	var gotX, gotY big.Int
	newConstant.X.BigInt(&gotX)
	newConstant.Y.BigInt(&gotY)

	// Expected values from DoryVerifier11Stripped.sol
	expectedX := new(big.Int)
	expectedX.SetString("20313953450870273575159174035284012182538915061906268849493852326816484748739", 10)
	expectedY := new(big.Int)
	expectedY.SetString("4028015817004929679132736218506636934472674675427880554265596495955190103187", 10)

	if gotX.Cmp(expectedX) != 0 {
		t.Fatalf("CONSTANT_X mismatch:\n  got:    %s\n  expect: %s", gotX.String(), expectedX.String())
	}
	if gotY.Cmp(expectedY) != 0 {
		t.Fatalf("CONSTANT_Y mismatch:\n  got:    %s\n  expect: %s", gotY.String(), expectedY.String())
	}

	t.Logf("Folded constant verified: (%s, %s)", gotX.String(), gotY.String())
	t.Log("Stripped verifier constants are correct!")
}
