package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

func TestGTConversion(t *testing.T) {
	w, err := LoadWitnessJSON("../testdata/dory_witness.json")
	if err != nil {
		t.Fatalf("failed to load witness JSON: %v", err)
	}

	// Parse the test pairing from JSON (ark-bn254 computed e(G1_0, G2_0))
	arkGT := parseGT(w.TestPairing)

	// Compute the same pairing natively using gnark-crypto
	g1Ark := parseG1(w.Setup.G1_0)
	g2Ark := parseG2(w.Setup.G2_0)

	// Get native gnark-crypto points from the parsed gnark circuit types
	// We need to convert back from gnark circuit types to gnark-crypto native types
	// Actually, let's just compute the pairing directly from the JSON hex values
	var g1Native bn254.G1Affine
	g1Native.X.SetBigInt(hexToBigInt(w.Setup.G1_0.X))
	g1Native.Y.SetBigInt(hexToBigInt(w.Setup.G1_0.Y))

	var g2Native bn254.G2Affine
	g2Native.X.A0.SetBigInt(hexToBigInt(w.Setup.G2_0.X.A0))
	g2Native.X.A1.SetBigInt(hexToBigInt(w.Setup.G2_0.X.A1))
	g2Native.Y.A0.SetBigInt(hexToBigInt(w.Setup.G2_0.Y.A0))
	g2Native.Y.A1.SetBigInt(hexToBigInt(w.Setup.G2_0.Y.A1))

	// Compute native pairing
	nativeGT, err := bn254.Pair([]bn254.G1Affine{g1Native}, []bn254.G2Affine{g2Native})
	if err != nil {
		t.Fatalf("native pairing failed: %v", err)
	}

	// Convert native pairing result to gnark circuit type using NewGTEl
	gnarkGT := sw_bn254.NewGTEl(nativeGT)

	// Now compare: arkGT (from ark-bn254 via parseGT) vs gnarkGT (from gnark-crypto pairing)
	t.Logf("arkGT.A0 limbs: %v", arkGT.A0.Limbs)
	t.Logf("gnarkGT.A0 limbs: %v", gnarkGT.A0.Limbs)

	// Also compare by converting both back to tower form
	_ = g1Ark
	_ = g2Ark

	// Reconstruct the ark GT value (from JSON) in gnark-crypto native form
	var arkGTNative bn254.GT
	setFpFromHex := func(dst *bn254.GT, g GTJSON) {
		dst.C0.B0.A0.SetBigInt(hexToBigInt(g.C0.B0.A0))
		dst.C0.B0.A1.SetBigInt(hexToBigInt(g.C0.B0.A1))
		dst.C0.B1.A0.SetBigInt(hexToBigInt(g.C0.B1.A0))
		dst.C0.B1.A1.SetBigInt(hexToBigInt(g.C0.B1.A1))
		dst.C0.B2.A0.SetBigInt(hexToBigInt(g.C0.B2.A0))
		dst.C0.B2.A1.SetBigInt(hexToBigInt(g.C0.B2.A1))
		dst.C1.B0.A0.SetBigInt(hexToBigInt(g.C1.B0.A0))
		dst.C1.B0.A1.SetBigInt(hexToBigInt(g.C1.B0.A1))
		dst.C1.B1.A0.SetBigInt(hexToBigInt(g.C1.B1.A0))
		dst.C1.B1.A1.SetBigInt(hexToBigInt(g.C1.B1.A1))
		dst.C1.B2.A0.SetBigInt(hexToBigInt(g.C1.B2.A0))
		dst.C1.B2.A1.SetBigInt(hexToBigInt(g.C1.B2.A1))
	}
	setFpFromHex(&arkGTNative, w.TestPairing)

	// Compare the native GT values
	if arkGTNative.Equal(&nativeGT) {
		t.Log("ark-bn254 and gnark-crypto pairings produce IDENTICAL GT values")
	} else {
		t.Log("ark-bn254 and gnark-crypto pairings produce DIFFERENT GT values")
		t.Logf("ark C0.B0.A0: %s", arkGTNative.C0.B0.A0.String())
		t.Logf("gnark C0.B0.A0: %s", nativeGT.C0.B0.A0.String())
		t.Logf("ark C0.B0.A1: %s", arkGTNative.C0.B0.A1.String())
		t.Logf("gnark C0.B0.A1: %s", nativeGT.C0.B0.A1.String())
	}
}
