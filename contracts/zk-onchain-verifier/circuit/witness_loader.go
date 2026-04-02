package circuit

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimcbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// WitnessJSON matches the JSON structure exported by the Rust export_witness example.
type WitnessJSON struct {
	NumRounds int      `json:"num_rounds"`
	Alpha     []string `json:"alpha"`
	Beta      []string `json:"beta"`
	Gamma     string   `json:"gamma"`
	D         string   `json:"d"`
	S1Coords  []string `json:"s1_coords"`
	S2Coords  []string `json:"s2_coords"`

	Commitment GTJSON `json:"commitment"`
	Evaluation string `json:"evaluation"`

	VMV_C  GTJSON `json:"vmv_c"`
	VMV_D2 GTJSON `json:"vmv_d2"`
	VMV_E1 G1JSON `json:"vmv_e1"`

	FirstMessages  []FirstMessageJSON  `json:"first_messages"`
	SecondMessages []SecondMessageJSON `json:"second_messages"`

	FinalE1 G1JSON `json:"final_e1"`
	FinalE2 G2JSON `json:"final_e2"`

	FinalP1G2 G2JSON `json:"final_p1_g2"`
	FinalP2G2 G2JSON `json:"final_p2_g2"`

	TestPairing        GTJSON   `json:"test_pairing"`
	DebugCAfterRounds  []GTJSON `json:"debug_c_after_rounds"`
	DebugD1AfterRounds []GTJSON `json:"debug_d1_after_rounds"`
	DebugD2AfterRounds []GTJSON `json:"debug_d2_after_rounds"`

	Setup SetupJSON `json:"setup"`
}

type G1JSON struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type Fq2JSON struct {
	A0 string `json:"a0"`
	A1 string `json:"a1"`
}

type G2JSON struct {
	X Fq2JSON `json:"x"`
	Y Fq2JSON `json:"y"`
}

type Fq6JSON struct {
	B0 Fq2JSON `json:"b0"`
	B1 Fq2JSON `json:"b1"`
	B2 Fq2JSON `json:"b2"`
}

type GTJSON struct {
	C0 Fq6JSON `json:"c0"`
	C1 Fq6JSON `json:"c1"`
}

type FirstMessageJSON struct {
	D1Left  GTJSON `json:"d1_left"`
	D1Right GTJSON `json:"d1_right"`
	D2Left  GTJSON `json:"d2_left"`
	D2Right GTJSON `json:"d2_right"`
	E1Beta  G1JSON `json:"e1_beta"`
	E2Beta  G2JSON `json:"e2_beta"`
}

type SecondMessageJSON struct {
	CPlus   GTJSON `json:"c_plus"`
	CMinus  GTJSON `json:"c_minus"`
	E1Plus  G1JSON `json:"e1_plus"`
	E1Minus G1JSON `json:"e1_minus"`
	E2Plus  G2JSON `json:"e2_plus"`
	E2Minus G2JSON `json:"e2_minus"`
}

type SetupJSON struct {
	Chi     []GTJSON `json:"chi"`
	Delta1L []GTJSON `json:"delta_1l"`
	Delta1R []GTJSON `json:"delta_1r"`
	Delta2L []GTJSON `json:"delta_2l"`
	Delta2R []GTJSON `json:"delta_2r"`
	G1_0    G1JSON   `json:"g1_0"`
	G2_0    G2JSON   `json:"g2_0"`
	H1      G1JSON   `json:"h1"`
	H2      G2JSON   `json:"h2"`
	HT      GTJSON   `json:"ht"`
}

func LoadWitnessJSON(path string) (*WitnessJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w WitnessJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func hexToBigInt(s string) *big.Int {
	b := new(big.Int)
	if len(s) > 2 && s[:2] == "0x" {
		b.SetString(s[2:], 16)
	} else {
		b.SetString(s, 16)
	}
	return b
}

func parseScalar(s string) emulated.Element[sw_bn254.ScalarField] {
	return emulated.ValueOf[sw_bn254.ScalarField](hexToBigInt(s))
}

func parseG1(g G1JSON) sw_bn254.G1Affine {
	var p bn254.G1Affine
	p.X.SetBigInt(hexToBigInt(g.X))
	p.Y.SetBigInt(hexToBigInt(g.Y))
	return sw_bn254.NewG1Affine(p)
}

func parseG2(g G2JSON) sw_bn254.G2Affine {
	var p bn254.G2Affine
	p.X.A0.SetBigInt(hexToBigInt(g.X.A0))
	p.X.A1.SetBigInt(hexToBigInt(g.X.A1))
	p.Y.A0.SetBigInt(hexToBigInt(g.Y.A0))
	p.Y.A1.SetBigInt(hexToBigInt(g.Y.A1))
	return sw_bn254.NewG2Affine(p)
}

// parseGT converts the ark-bn254 Fq12 tower representation to gnark's E12.
func parseGT(g GTJSON) fields_bn254.E12 {
	var gt bn254.GT

	setFp := func(dst *fp.Element, hex string) {
		dst.SetBigInt(hexToBigInt(hex))
	}

	setFp(&gt.C0.B0.A0, g.C0.B0.A0)
	setFp(&gt.C0.B0.A1, g.C0.B0.A1)
	setFp(&gt.C0.B1.A0, g.C0.B1.A0)
	setFp(&gt.C0.B1.A1, g.C0.B1.A1)
	setFp(&gt.C0.B2.A0, g.C0.B2.A0)
	setFp(&gt.C0.B2.A1, g.C0.B2.A1)
	setFp(&gt.C1.B0.A0, g.C1.B0.A0)
	setFp(&gt.C1.B0.A1, g.C1.B0.A1)
	setFp(&gt.C1.B1.A0, g.C1.B1.A0)
	setFp(&gt.C1.B1.A1, g.C1.B1.A1)
	setFp(&gt.C1.B2.A0, g.C1.B2.A0)
	setFp(&gt.C1.B2.A1, g.C1.B2.A1)

	return sw_bn254.NewGTEl(gt)
}

// nativeGTFromJSON converts GTJSON to a native bn254.GT
func nativeGTFromJSON(g GTJSON) bn254.GT {
	var gt bn254.GT
	gt.C0.B0.A0.SetBigInt(hexToBigInt(g.C0.B0.A0))
	gt.C0.B0.A1.SetBigInt(hexToBigInt(g.C0.B0.A1))
	gt.C0.B1.A0.SetBigInt(hexToBigInt(g.C0.B1.A0))
	gt.C0.B1.A1.SetBigInt(hexToBigInt(g.C0.B1.A1))
	gt.C0.B2.A0.SetBigInt(hexToBigInt(g.C0.B2.A0))
	gt.C0.B2.A1.SetBigInt(hexToBigInt(g.C0.B2.A1))
	gt.C1.B0.A0.SetBigInt(hexToBigInt(g.C1.B0.A0))
	gt.C1.B0.A1.SetBigInt(hexToBigInt(g.C1.B0.A1))
	gt.C1.B1.A0.SetBigInt(hexToBigInt(g.C1.B1.A0))
	gt.C1.B1.A1.SetBigInt(hexToBigInt(g.C1.B1.A1))
	gt.C1.B2.A0.SetBigInt(hexToBigInt(g.C1.B2.A0))
	gt.C1.B2.A1.SetBigInt(hexToBigInt(g.C1.B2.A1))
	return gt
}

// nativeGTExp computes base^exp natively and returns gnark circuit E12
func nativeGTExp(base GTJSON, exp *big.Int) fields_bn254.E12 {
	gt := nativeGTFromJSON(base)
	var result bn254.GT
	result.Exp(gt, exp)
	return sw_bn254.NewGTEl(result)
}

// AssignWitness creates a DoryVerifierCircuit (NumRounds-round) witness from the JSON data.
// GT exponentiations are computed natively and provided as witness values.
func (w *WitnessJSON) AssignWitness() (*DoryVerifierCircuit, error) {
	if w.NumRounds != NumRounds {
		return nil, fmt.Errorf("expected %d rounds, got %d", NumRounds, w.NumRounds)
	}

	r := ecc.BN254.ScalarField()
	var c DoryVerifierCircuit

	for i := 0; i < NumRounds; i++ {
		c.Alpha[i] = parseScalar(w.Alpha[i])
		c.Beta[i] = parseScalar(w.Beta[i])
		c.S1Coords[i] = parseScalar(w.S1Coords[i])
		c.S2Coords[i] = parseScalar(w.S2Coords[i])
	}
	c.Gamma = parseScalar(w.Gamma)
	c.D = parseScalar(w.D)
	c.Commitment = parseGT(w.Commitment)
	c.Evaluation = parseScalar(w.Evaluation)

	c.VMV_C = parseGT(w.VMV_C)
	c.VMV_D2 = parseGT(w.VMV_D2)
	c.VMV_E1 = parseG1(w.VMV_E1)

	// Native G1 E1 accumulation (witness-provided to circuit)
	var accumE1 bn254.G1Affine
	accumE1.X.SetBigInt(hexToBigInt(w.VMV_E1.X))
	accumE1.Y.SetBigInt(hexToBigInt(w.VMV_E1.Y))

	for i := 0; i < NumRounds; i++ {
		fm := w.FirstMessages[i]
		c.D1Right[i] = parseGT(fm.D1Right)
		c.D2Right[i] = parseGT(fm.D2Right)

		sm := w.SecondMessages[i]

		alpha := hexToBigInt(w.Alpha[i])
		beta := hexToBigInt(w.Beta[i])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		betaInv := new(big.Int).ModInverse(beta, r)
		alphaBeta := new(big.Int).Mul(alpha, beta)
		alphaBeta.Mod(alphaBeta, r)
		alphaInvBetaInv := new(big.Int).Mul(alphaInv, betaInv)
		alphaInvBetaInv.Mod(alphaInvBetaInv, r)

		round := NumRounds - i // circuit's round variable

		// C accumulation GT exp results
		if i == 0 {
			c.D2Scaled[0] = nativeGTExp(w.VMV_D2, beta)
			c.D1Scaled[0] = nativeGTExp(w.Commitment, betaInv)
		} else {
			c.D2Scaled[i] = nativeGTExp(w.DebugD2AfterRounds[i-1], beta)
			c.D1Scaled[i] = nativeGTExp(w.DebugD1AfterRounds[i-1], betaInv)
		}
		c.CPScaled[i] = nativeGTExp(sm.CPlus, alpha)
		c.CMScaled[i] = nativeGTExp(sm.CMinus, alphaInv)

		// D1 accumulation GT exp results
		c.D1LScaled[i] = nativeGTExp(fm.D1Left, alpha)
		c.D1LSSetup[i] = nativeGTExp(w.Setup.Delta1L[round], alphaBeta)
		c.D1RSSetup[i] = nativeGTExp(w.Setup.Delta1R[round], beta)

		// D2 accumulation GT exp results
		c.D2LScaled[i] = nativeGTExp(fm.D2Left, alphaInv)
		c.D2LSSetup[i] = nativeGTExp(w.Setup.Delta2L[round], alphaInvBetaInv)
		c.D2RSSetup[i] = nativeGTExp(w.Setup.Delta2R[round], betaInv)

		// Native G1 E1 accumulation: accumE1 += β·E1Beta + α·E1Plus + α⁻¹·E1Minus
		{
			var e1b, e1p, e1m bn254.G1Affine
			e1b.X.SetBigInt(hexToBigInt(fm.E1Beta.X))
			e1b.Y.SetBigInt(hexToBigInt(fm.E1Beta.Y))
			e1b.ScalarMultiplication(&e1b, beta)

			e1p.X.SetBigInt(hexToBigInt(sm.E1Plus.X))
			e1p.Y.SetBigInt(hexToBigInt(sm.E1Plus.Y))
			e1p.ScalarMultiplication(&e1p, alpha)

			e1m.X.SetBigInt(hexToBigInt(sm.E1Minus.X))
			e1m.Y.SetBigInt(hexToBigInt(sm.E1Minus.Y))
			e1m.ScalarMultiplication(&e1m, alphaInv)

			accumE1.Add(&accumE1, &e1b)
			accumE1.Add(&accumE1, &e1p)
			accumE1.Add(&accumE1, &e1m)
		}

		// Checkpoints
		c.CheckpointC[i] = parseGT(w.DebugCAfterRounds[i])
		c.CheckpointD1[i] = parseGT(w.DebugD1AfterRounds[i])
		c.CheckpointD2[i] = parseGT(w.DebugD2AfterRounds[i])
	}

	// Assign accumulated G1 E1 point
	c.AccumE1 = sw_bn254.NewG1Affine(accumE1)

	c.FinalE1 = parseG1(w.FinalE1)
	c.FinalP1G2 = parseG2(w.FinalP1G2)
	c.FinalP2G2 = parseG2(w.FinalP2G2)

	// Final section GT exp results
	d := hexToBigInt(w.D)
	dInv := new(big.Int).ModInverse(d, r)
	dSq := new(big.Int).Mul(d, d)
	dSq.Mod(dSq, r)

	// Compute s1Acc, s2Acc natively
	s1Acc := big.NewInt(1)
	s2Acc := big.NewInt(1)
	for roundIdx := 0; roundIdx < NumRounds; roundIdx++ {
		coordIdx := NumRounds - 1 - roundIdx
		alpha := hexToBigInt(w.Alpha[roundIdx])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		y := hexToBigInt(w.S1Coords[coordIdx])
		x := hexToBigInt(w.S2Coords[coordIdx])
		oneMinusY := new(big.Int).Sub(big.NewInt(1), y)
		oneMinusY.Mod(oneMinusY, r)
		oneMinusX := new(big.Int).Sub(big.NewInt(1), x)
		oneMinusX.Mod(oneMinusX, r)
		s1Factor := new(big.Int).Mul(alpha, oneMinusY)
		s1Factor.Add(s1Factor, y)
		s1Factor.Mod(s1Factor, r)
		s2Factor := new(big.Int).Mul(alphaInv, oneMinusX)
		s2Factor.Add(s2Factor, x)
		s2Factor.Mod(s2Factor, r)
		s1Acc.Mul(s1Acc, s1Factor)
		s1Acc.Mod(s1Acc, r)
		s2Acc.Mul(s2Acc, s2Factor)
		s2Acc.Mod(s2Acc, r)
	}
	sProduct := new(big.Int).Mul(s1Acc, s2Acc)
	sProduct.Mod(sProduct, r)

	c.SProduct = emulated.ValueOf[sw_bn254.ScalarField](sProduct)

	lastRoundIdx := NumRounds - 1
	c.HTScaled = nativeGTExp(w.Setup.HT, sProduct)
	c.D2Final = nativeGTExp(w.DebugD2AfterRounds[lastRoundIdx], d)
	c.D1Final = nativeGTExp(w.DebugD1AfterRounds[lastRoundIdx], dInv)
	c.D2InitScaled = nativeGTExp(w.VMV_D2, dSq)

	// Setup
	for i := 0; i <= NumRounds; i++ {
		c.SetupChi[i] = parseGT(w.Setup.Chi[i])
	}
	c.SetupG1_0 = parseG1(w.Setup.G1_0)
	c.SetupG2_0 = parseG2(w.Setup.G2_0)
	c.SetupH1 = parseG1(w.Setup.H1)
	c.SetupH2 = parseG2(w.Setup.H2)

	// Compute InputHash = MiMC(packed values) matching the in-circuit hash.
	// Scalar field values are hashed as single Fr elements (not 4 limbs).
	// Fp values are packed into 2×128-bit values per element.
	// Total: 48 scalar + 24 Fp = 72 absorptions.
	mimcH := mimcbn254.NewMiMC()
	mask64 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	shift64 := new(big.Int).Lsh(big.NewInt(1), 64)

	// Hash a scalar field value as a single Fr element
	writeScalar := func(v *big.Int) {
		var frEl fr.Element
		frEl.SetBigInt(v)
		b := frEl.Marshal()
		mimcH.Write(b)
	}

	// Hash an Fp value as 2×128-bit packed limbs
	writeFpPacked := func(v *big.Int) {
		limb0 := new(big.Int).And(v, mask64)
		limb1 := new(big.Int).And(new(big.Int).Rsh(v, 64), mask64)
		limb2 := new(big.Int).And(new(big.Int).Rsh(v, 128), mask64)
		limb3 := new(big.Int).And(new(big.Int).Rsh(v, 192), mask64)
		lo := new(big.Int).Add(limb0, new(big.Int).Mul(limb1, shift64))
		hi := new(big.Int).Add(limb2, new(big.Int).Mul(limb3, shift64))
		var loFr, hiFr fr.Element
		loFr.SetBigInt(lo)
		hiFr.SetBigInt(hi)
		mimcH.Write(loFr.Marshal())
		mimcH.Write(hiFr.Marshal())
	}

	// Hash in same order as circuit Define()
	for i := 0; i < NumRounds; i++ {
		writeScalar(hexToBigInt(w.Alpha[i]))
	}
	for i := 0; i < NumRounds; i++ {
		writeScalar(hexToBigInt(w.Beta[i]))
	}
	writeScalar(hexToBigInt(w.Gamma))
	writeScalar(hexToBigInt(w.D))
	for i := 0; i < NumRounds; i++ {
		writeScalar(hexToBigInt(w.S1Coords[i]))
	}
	for i := 0; i < NumRounds; i++ {
		writeScalar(hexToBigInt(w.S2Coords[i]))
	}
	// Commitment: 12 Fp elements in gnark E12 Karabina representation.
	// NewGTEl applies: A0..A5 = a0 - 9*a1, A6..A11 = a1 (Karabina compressed form).
	commitGT := nativeGTFromJSON(w.Commitment)
	nine := new(fp.Element).SetUint64(9)
	karabina := func(a0, a1 *fp.Element) *big.Int {
		var t, res fp.Element
		t.Mul(nine, a1)
		res.Sub(a0, &t)
		var b big.Int
		res.BigInt(&b)
		return &b
	}
	fpToBig := func(v *fp.Element) *big.Int {
		var b big.Int
		v.BigInt(&b)
		return &b
	}
	commitFpBigs := []*big.Int{
		karabina(&commitGT.C0.B0.A0, &commitGT.C0.B0.A1), // A0
		karabina(&commitGT.C1.B0.A0, &commitGT.C1.B0.A1), // A1
		karabina(&commitGT.C0.B1.A0, &commitGT.C0.B1.A1), // A2
		karabina(&commitGT.C1.B1.A0, &commitGT.C1.B1.A1), // A3
		karabina(&commitGT.C0.B2.A0, &commitGT.C0.B2.A1), // A4
		karabina(&commitGT.C1.B2.A0, &commitGT.C1.B2.A1), // A5
		fpToBig(&commitGT.C0.B0.A1),                       // A6
		fpToBig(&commitGT.C1.B0.A1),                       // A7
		fpToBig(&commitGT.C0.B1.A1),                       // A8
		fpToBig(&commitGT.C1.B1.A1),                       // A9
		fpToBig(&commitGT.C0.B2.A1),                       // A10
		fpToBig(&commitGT.C1.B2.A1),                       // A11
	}
	for _, fpBig := range commitFpBigs {
		writeFpPacked(fpBig)
	}
	writeScalar(hexToBigInt(w.Evaluation))
	writeScalar(sProduct)

	inputHashBytes := mimcH.Sum(nil)
	var inputHashFr fr.Element
	inputHashFr.SetBytes(inputHashBytes)
	var inputHashBig big.Int
	inputHashFr.BigInt(&inputHashBig)
	c.InputHash = inputHashBig

	return &c, nil
}

// AssignWitness4 creates a DoryVerifier4Circuit witness from the JSON data.
// GT exponentiations are computed natively and provided as witness values.
func (w *WitnessJSON) AssignWitness4() (*DoryVerifier4Circuit, error) {
	if w.NumRounds != 4 {
		return nil, fmt.Errorf("expected 4 rounds, got %d", w.NumRounds)
	}

	r := ecc.BN254.ScalarField()
	var c DoryVerifier4Circuit

	for i := 0; i < 4; i++ {
		c.Alpha[i] = parseScalar(w.Alpha[i])
		c.Beta[i] = parseScalar(w.Beta[i])
		c.S1Coords[i] = parseScalar(w.S1Coords[i])
		c.S2Coords[i] = parseScalar(w.S2Coords[i])
	}
	c.Gamma = parseScalar(w.Gamma)
	c.D = parseScalar(w.D)
	c.Commitment = parseGT(w.Commitment)
	c.Evaluation = parseScalar(w.Evaluation)

	c.VMV_C = parseGT(w.VMV_C)
	c.VMV_D2 = parseGT(w.VMV_D2)
	c.VMV_E1 = parseG1(w.VMV_E1)

	// Replay the accumulation natively to get GT exponentiation inputs
	var gtD1Native, gtD2Native bn254.GT
	gtD1Native = nativeGTFromJSON(w.Commitment)
	gtD2Native = nativeGTFromJSON(w.VMV_D2)

	// Native G1 E1 accumulation (witness-provided to circuit)
	var accumE1 bn254.G1Affine
	accumE1.X.SetBigInt(hexToBigInt(w.VMV_E1.X))
	accumE1.Y.SetBigInt(hexToBigInt(w.VMV_E1.Y))

	for i := 0; i < 4; i++ {
		fm := w.FirstMessages[i]
		c.D1Right[i] = parseGT(fm.D1Right)
		c.D2Right[i] = parseGT(fm.D2Right)

		sm := w.SecondMessages[i]

		alpha := hexToBigInt(w.Alpha[i])
		beta := hexToBigInt(w.Beta[i])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		betaInv := new(big.Int).ModInverse(beta, r)
		alphaBeta := new(big.Int).Mul(alpha, beta)
		alphaBeta.Mod(alphaBeta, r)
		alphaInvBetaInv := new(big.Int).Mul(alphaInv, betaInv)
		alphaInvBetaInv.Mod(alphaInvBetaInv, r)

		round := 4 - i // circuit's round variable

		// C accumulation GT exp results
		c.D2Scaled[i] = nativeGTExp(w.DebugD2AfterRounds[max(0, i-1)], beta)
		c.D1Scaled[i] = nativeGTExp(w.DebugD1AfterRounds[max(0, i-1)], betaInv)
		if i == 0 {
			// First round uses initial D2 and D1 (commitment)
			c.D2Scaled[0] = nativeGTExp(w.VMV_D2, beta)
			c.D1Scaled[0] = nativeGTExp(w.Commitment, betaInv)
		}
		c.CPScaled[i] = nativeGTExp(sm.CPlus, alpha)
		c.CMScaled[i] = nativeGTExp(sm.CMinus, alphaInv)

		// D1 accumulation GT exp results
		c.D1LScaled[i] = nativeGTExp(fm.D1Left, alpha)
		c.D1LSSetup[i] = nativeGTExp(w.Setup.Delta1L[round], alphaBeta)
		c.D1RSSetup[i] = nativeGTExp(w.Setup.Delta1R[round], beta)

		// D2 accumulation GT exp results
		c.D2LScaled[i] = nativeGTExp(fm.D2Left, alphaInv)
		c.D2LSSetup[i] = nativeGTExp(w.Setup.Delta2L[round], alphaInvBetaInv)
		c.D2RSSetup[i] = nativeGTExp(w.Setup.Delta2R[round], betaInv)

		// Native G1 E1 accumulation: accumE1 += β·E1Beta + α·E1Plus + α⁻¹·E1Minus
		{
			var e1b, e1p, e1m bn254.G1Affine
			e1b.X.SetBigInt(hexToBigInt(fm.E1Beta.X))
			e1b.Y.SetBigInt(hexToBigInt(fm.E1Beta.Y))
			e1b.ScalarMultiplication(&e1b, beta)

			e1p.X.SetBigInt(hexToBigInt(sm.E1Plus.X))
			e1p.Y.SetBigInt(hexToBigInt(sm.E1Plus.Y))
			e1p.ScalarMultiplication(&e1p, alpha)

			e1m.X.SetBigInt(hexToBigInt(sm.E1Minus.X))
			e1m.Y.SetBigInt(hexToBigInt(sm.E1Minus.Y))
			e1m.ScalarMultiplication(&e1m, alphaInv)

			accumE1.Add(&accumE1, &e1b)
			accumE1.Add(&accumE1, &e1p)
			accumE1.Add(&accumE1, &e1m)
		}

		// Update native D1/D2 for next round
		var tmp bn254.GT
		gtD1Native = nativeGTFromJSON(fm.D1Left)
		gtD1Native.Exp(gtD1Native, alpha)
		tmp = nativeGTFromJSON(fm.D1Right)
		gtD1Native.Mul(&gtD1Native, &tmp)
		tmp = nativeGTFromJSON(w.Setup.Delta1L[round])
		tmp.Exp(tmp, alphaBeta)
		gtD1Native.Mul(&gtD1Native, &tmp)
		tmp = nativeGTFromJSON(w.Setup.Delta1R[round])
		tmp.Exp(tmp, beta)
		gtD1Native.Mul(&gtD1Native, &tmp)

		gtD2Native = nativeGTFromJSON(fm.D2Left)
		gtD2Native.Exp(gtD2Native, alphaInv)
		tmp = nativeGTFromJSON(fm.D2Right)
		gtD2Native.Mul(&gtD2Native, &tmp)
		tmp = nativeGTFromJSON(w.Setup.Delta2L[round])
		tmp.Exp(tmp, alphaInvBetaInv)
		gtD2Native.Mul(&gtD2Native, &tmp)
		tmp = nativeGTFromJSON(w.Setup.Delta2R[round])
		tmp.Exp(tmp, betaInv)
		gtD2Native.Mul(&gtD2Native, &tmp)

		// Checkpoints
		c.CheckpointC[i] = parseGT(w.DebugCAfterRounds[i])
		c.CheckpointD1[i] = parseGT(w.DebugD1AfterRounds[i])
		c.CheckpointD2[i] = parseGT(w.DebugD2AfterRounds[i])
	}

	// Assign accumulated G1 E1 point
	c.AccumE1 = sw_bn254.NewG1Affine(accumE1)

	c.FinalE1 = parseG1(w.FinalE1)
	c.FinalP1G2 = parseG2(w.FinalP1G2)
	c.FinalP2G2 = parseG2(w.FinalP2G2)

	// Final section GT exp results
	d := hexToBigInt(w.D)
	dInv := new(big.Int).ModInverse(d, r)
	dSq := new(big.Int).Mul(d, d)
	dSq.Mod(dSq, r)

	// Compute s1Acc, s2Acc natively
	s1Acc := big.NewInt(1)
	s2Acc := big.NewInt(1)
	for roundIdx := 0; roundIdx < 4; roundIdx++ {
		coordIdx := 3 - roundIdx
		alpha := hexToBigInt(w.Alpha[roundIdx])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		y := hexToBigInt(w.S1Coords[coordIdx])
		x := hexToBigInt(w.S2Coords[coordIdx])
		oneMinusY := new(big.Int).Sub(big.NewInt(1), y)
		oneMinusY.Mod(oneMinusY, r)
		oneMinusX := new(big.Int).Sub(big.NewInt(1), x)
		oneMinusX.Mod(oneMinusX, r)
		s1Factor := new(big.Int).Mul(alpha, oneMinusY)
		s1Factor.Add(s1Factor, y)
		s1Factor.Mod(s1Factor, r)
		s2Factor := new(big.Int).Mul(alphaInv, oneMinusX)
		s2Factor.Add(s2Factor, x)
		s2Factor.Mod(s2Factor, r)
		s1Acc.Mul(s1Acc, s1Factor)
		s1Acc.Mod(s1Acc, r)
		s2Acc.Mul(s2Acc, s2Factor)
		s2Acc.Mod(s2Acc, r)
	}
	sProduct := new(big.Int).Mul(s1Acc, s2Acc)
	sProduct.Mod(sProduct, r)

	// SProduct public input binds the evaluation point to the proof
	c.SProduct = emulated.ValueOf[sw_bn254.ScalarField](sProduct)

	c.HTScaled = nativeGTExp(w.Setup.HT, sProduct)
	c.D2Final = nativeGTExp(w.DebugD2AfterRounds[3], d)
	c.D1Final = nativeGTExp(w.DebugD1AfterRounds[3], dInv)
	c.D2InitScaled = nativeGTExp(w.VMV_D2, dSq)

	// Setup
	for i := 0; i <= 4; i++ {
		c.SetupChi[i] = parseGT(w.Setup.Chi[i])
	}
	c.SetupG1_0 = parseG1(w.Setup.G1_0)
	c.SetupG2_0 = parseG2(w.Setup.G2_0)
	c.SetupH1 = parseG1(w.Setup.H1)
	c.SetupH2 = parseG2(w.Setup.H2)

	return &c, nil
}

// JoltExportJSON is the top-level structure of jolt_onchain_proof.json.
type JoltExportJSON struct {
	DoryWitness *WitnessJSON `json:"dory_witness"`
}

// LoadJoltExportWitness loads the dory_witness from a jolt_onchain_proof.json file.
func LoadJoltExportWitness(path string) (*WitnessJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var export JoltExportJSON
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, err
	}
	if export.DoryWitness == nil {
		return nil, fmt.Errorf("dory_witness field is null or missing in %s", path)
	}
	return export.DoryWitness, nil
}

// AssignWitness7 creates a DoryVerifier7Circuit (7-round) witness from the JSON data.
func (w *WitnessJSON) AssignWitness7() (*DoryVerifier7Circuit, error) {
	if w.NumRounds != NumRounds7 {
		return nil, fmt.Errorf("expected %d rounds, got %d", NumRounds7, w.NumRounds)
	}

	r := ecc.BN254.ScalarField()
	var c DoryVerifier7Circuit

	for i := 0; i < NumRounds7; i++ {
		c.Alpha[i] = parseScalar(w.Alpha[i])
		c.Beta[i] = parseScalar(w.Beta[i])
		c.S1Coords[i] = parseScalar(w.S1Coords[i])
		c.S2Coords[i] = parseScalar(w.S2Coords[i])
	}
	c.Gamma = parseScalar(w.Gamma)
	c.D = parseScalar(w.D)
	c.Commitment = parseGT(w.Commitment)
	c.Evaluation = parseScalar(w.Evaluation)

	c.VMV_C = parseGT(w.VMV_C)
	c.VMV_D2 = parseGT(w.VMV_D2)
	c.VMV_E1 = parseG1(w.VMV_E1)

	var accumE1 bn254.G1Affine
	accumE1.X.SetBigInt(hexToBigInt(w.VMV_E1.X))
	accumE1.Y.SetBigInt(hexToBigInt(w.VMV_E1.Y))

	for i := 0; i < NumRounds7; i++ {
		fm := w.FirstMessages[i]
		c.D1Right[i] = parseGT(fm.D1Right)
		c.D2Right[i] = parseGT(fm.D2Right)

		sm := w.SecondMessages[i]

		alpha := hexToBigInt(w.Alpha[i])
		beta := hexToBigInt(w.Beta[i])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		betaInv := new(big.Int).ModInverse(beta, r)
		alphaBeta := new(big.Int).Mul(alpha, beta)
		alphaBeta.Mod(alphaBeta, r)
		alphaInvBetaInv := new(big.Int).Mul(alphaInv, betaInv)
		alphaInvBetaInv.Mod(alphaInvBetaInv, r)

		round := NumRounds7 - i

		if i == 0 {
			c.D2Scaled[0] = nativeGTExp(w.VMV_D2, beta)
			c.D1Scaled[0] = nativeGTExp(w.Commitment, betaInv)
		} else {
			c.D2Scaled[i] = nativeGTExp(w.DebugD2AfterRounds[i-1], beta)
			c.D1Scaled[i] = nativeGTExp(w.DebugD1AfterRounds[i-1], betaInv)
		}
		c.CPScaled[i] = nativeGTExp(sm.CPlus, alpha)
		c.CMScaled[i] = nativeGTExp(sm.CMinus, alphaInv)

		c.D1LScaled[i] = nativeGTExp(fm.D1Left, alpha)
		c.D1LSSetup[i] = nativeGTExp(w.Setup.Delta1L[round], alphaBeta)
		c.D1RSSetup[i] = nativeGTExp(w.Setup.Delta1R[round], beta)

		c.D2LScaled[i] = nativeGTExp(fm.D2Left, alphaInv)
		c.D2LSSetup[i] = nativeGTExp(w.Setup.Delta2L[round], alphaInvBetaInv)
		c.D2RSSetup[i] = nativeGTExp(w.Setup.Delta2R[round], betaInv)

		{
			var e1b, e1p, e1m bn254.G1Affine
			e1b.X.SetBigInt(hexToBigInt(fm.E1Beta.X))
			e1b.Y.SetBigInt(hexToBigInt(fm.E1Beta.Y))
			e1b.ScalarMultiplication(&e1b, beta)

			e1p.X.SetBigInt(hexToBigInt(sm.E1Plus.X))
			e1p.Y.SetBigInt(hexToBigInt(sm.E1Plus.Y))
			e1p.ScalarMultiplication(&e1p, alpha)

			e1m.X.SetBigInt(hexToBigInt(sm.E1Minus.X))
			e1m.Y.SetBigInt(hexToBigInt(sm.E1Minus.Y))
			e1m.ScalarMultiplication(&e1m, alphaInv)

			accumE1.Add(&accumE1, &e1b)
			accumE1.Add(&accumE1, &e1p)
			accumE1.Add(&accumE1, &e1m)
		}

		c.CheckpointC[i] = parseGT(w.DebugCAfterRounds[i])
		c.CheckpointD1[i] = parseGT(w.DebugD1AfterRounds[i])
		c.CheckpointD2[i] = parseGT(w.DebugD2AfterRounds[i])
	}

	c.AccumE1 = sw_bn254.NewG1Affine(accumE1)
	c.FinalE1 = parseG1(w.FinalE1)
	c.FinalP1G2 = parseG2(w.FinalP1G2)
	c.FinalP2G2 = parseG2(w.FinalP2G2)

	d := hexToBigInt(w.D)
	dInv := new(big.Int).ModInverse(d, r)
	dSq := new(big.Int).Mul(d, d)
	dSq.Mod(dSq, r)

	s1Acc := big.NewInt(1)
	s2Acc := big.NewInt(1)
	for roundIdx := 0; roundIdx < NumRounds7; roundIdx++ {
		coordIdx := NumRounds7 - 1 - roundIdx
		alpha := hexToBigInt(w.Alpha[roundIdx])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		y := hexToBigInt(w.S1Coords[coordIdx])
		x := hexToBigInt(w.S2Coords[coordIdx])
		oneMinusY := new(big.Int).Sub(big.NewInt(1), y)
		oneMinusY.Mod(oneMinusY, r)
		oneMinusX := new(big.Int).Sub(big.NewInt(1), x)
		oneMinusX.Mod(oneMinusX, r)
		s1Factor := new(big.Int).Mul(alpha, oneMinusY)
		s1Factor.Add(s1Factor, y)
		s1Factor.Mod(s1Factor, r)
		s2Factor := new(big.Int).Mul(alphaInv, oneMinusX)
		s2Factor.Add(s2Factor, x)
		s2Factor.Mod(s2Factor, r)
		s1Acc.Mul(s1Acc, s1Factor)
		s1Acc.Mod(s1Acc, r)
		s2Acc.Mul(s2Acc, s2Factor)
		s2Acc.Mod(s2Acc, r)
	}
	sProduct := new(big.Int).Mul(s1Acc, s2Acc)
	sProduct.Mod(sProduct, r)
	c.SProduct = emulated.ValueOf[sw_bn254.ScalarField](sProduct)

	lastRoundIdx := NumRounds7 - 1
	c.HTScaled = nativeGTExp(w.Setup.HT, sProduct)
	c.D2Final = nativeGTExp(w.DebugD2AfterRounds[lastRoundIdx], d)
	c.D1Final = nativeGTExp(w.DebugD1AfterRounds[lastRoundIdx], dInv)
	c.D2InitScaled = nativeGTExp(w.VMV_D2, dSq)

	for i := 0; i <= NumRounds7; i++ {
		c.SetupChi[i] = parseGT(w.Setup.Chi[i])
	}
	c.SetupG1_0 = parseG1(w.Setup.G1_0)
	c.SetupG2_0 = parseG2(w.Setup.G2_0)
	c.SetupH1 = parseG1(w.Setup.H1)
	c.SetupH2 = parseG2(w.Setup.H2)

	// Compute InputHash = MiMC(packed values)
	mimcH := mimcbn254.NewMiMC()
	mask64 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	shift64 := new(big.Int).Lsh(big.NewInt(1), 64)

	writeScalar := func(v *big.Int) {
		var frEl fr.Element
		frEl.SetBigInt(v)
		b := frEl.Marshal()
		mimcH.Write(b)
	}

	writeFpPacked := func(v *big.Int) {
		limb0 := new(big.Int).And(v, mask64)
		limb1 := new(big.Int).And(new(big.Int).Rsh(v, 64), mask64)
		limb2 := new(big.Int).And(new(big.Int).Rsh(v, 128), mask64)
		limb3 := new(big.Int).And(new(big.Int).Rsh(v, 192), mask64)
		lo := new(big.Int).Add(limb0, new(big.Int).Mul(limb1, shift64))
		hi := new(big.Int).Add(limb2, new(big.Int).Mul(limb3, shift64))
		var loFr, hiFr fr.Element
		loFr.SetBigInt(lo)
		hiFr.SetBigInt(hi)
		mimcH.Write(loFr.Marshal())
		mimcH.Write(hiFr.Marshal())
	}

	for i := 0; i < NumRounds7; i++ {
		writeScalar(hexToBigInt(w.Alpha[i]))
	}
	for i := 0; i < NumRounds7; i++ {
		writeScalar(hexToBigInt(w.Beta[i]))
	}
	writeScalar(hexToBigInt(w.Gamma))
	writeScalar(hexToBigInt(w.D))
	for i := 0; i < NumRounds7; i++ {
		writeScalar(hexToBigInt(w.S1Coords[i]))
	}
	for i := 0; i < NumRounds7; i++ {
		writeScalar(hexToBigInt(w.S2Coords[i]))
	}
	commitGT := nativeGTFromJSON(w.Commitment)
	nine := new(fp.Element).SetUint64(9)
	karabina := func(a0, a1 *fp.Element) *big.Int {
		var t, res fp.Element
		t.Mul(nine, a1)
		res.Sub(a0, &t)
		var b big.Int
		res.BigInt(&b)
		return &b
	}
	fpToBig := func(v *fp.Element) *big.Int {
		var b big.Int
		v.BigInt(&b)
		return &b
	}
	commitFpBigs := []*big.Int{
		karabina(&commitGT.C0.B0.A0, &commitGT.C0.B0.A1),
		karabina(&commitGT.C1.B0.A0, &commitGT.C1.B0.A1),
		karabina(&commitGT.C0.B1.A0, &commitGT.C0.B1.A1),
		karabina(&commitGT.C1.B1.A0, &commitGT.C1.B1.A1),
		karabina(&commitGT.C0.B2.A0, &commitGT.C0.B2.A1),
		karabina(&commitGT.C1.B2.A0, &commitGT.C1.B2.A1),
		fpToBig(&commitGT.C0.B0.A1),
		fpToBig(&commitGT.C1.B0.A1),
		fpToBig(&commitGT.C0.B1.A1),
		fpToBig(&commitGT.C1.B1.A1),
		fpToBig(&commitGT.C0.B2.A1),
		fpToBig(&commitGT.C1.B2.A1),
	}
	for _, fpBig := range commitFpBigs {
		writeFpPacked(fpBig)
	}
	writeScalar(hexToBigInt(w.Evaluation))
	writeScalar(sProduct)

	inputHashBytes := mimcH.Sum(nil)
	var inputHashFr fr.Element
	inputHashFr.SetBytes(inputHashBytes)
	var inputHashBig big.Int
	inputHashFr.BigInt(&inputHashBig)
	c.InputHash = inputHashBig

	return &c, nil
}

func (w *WitnessJSON) AssignWitness9() (*DoryVerifier9Circuit, error) {
	if w.NumRounds != NumRounds9 {
		return nil, fmt.Errorf("expected %d rounds, got %d", NumRounds9, w.NumRounds)
	}

	r := ecc.BN254.ScalarField()
	var c DoryVerifier9Circuit

	for i := 0; i < NumRounds9; i++ {
		c.Alpha[i] = parseScalar(w.Alpha[i])
		c.Beta[i] = parseScalar(w.Beta[i])
		c.S1Coords[i] = parseScalar(w.S1Coords[i])
		c.S2Coords[i] = parseScalar(w.S2Coords[i])
	}
	c.Gamma = parseScalar(w.Gamma)
	c.D = parseScalar(w.D)
	c.Commitment = parseGT(w.Commitment)
	c.Evaluation = parseScalar(w.Evaluation)

	c.VMV_C = parseGT(w.VMV_C)
	c.VMV_D2 = parseGT(w.VMV_D2)
	c.VMV_E1 = parseG1(w.VMV_E1)

	var accumE1 bn254.G1Affine
	accumE1.X.SetBigInt(hexToBigInt(w.VMV_E1.X))
	accumE1.Y.SetBigInt(hexToBigInt(w.VMV_E1.Y))

	for i := 0; i < NumRounds9; i++ {
		fm := w.FirstMessages[i]
		c.D1Right[i] = parseGT(fm.D1Right)
		c.D2Right[i] = parseGT(fm.D2Right)

		sm := w.SecondMessages[i]

		alpha := hexToBigInt(w.Alpha[i])
		beta := hexToBigInt(w.Beta[i])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		betaInv := new(big.Int).ModInverse(beta, r)
		alphaBeta := new(big.Int).Mul(alpha, beta)
		alphaBeta.Mod(alphaBeta, r)
		alphaInvBetaInv := new(big.Int).Mul(alphaInv, betaInv)
		alphaInvBetaInv.Mod(alphaInvBetaInv, r)

		round := NumRounds9 - i

		if i == 0 {
			c.D2Scaled[0] = nativeGTExp(w.VMV_D2, beta)
			c.D1Scaled[0] = nativeGTExp(w.Commitment, betaInv)
		} else {
			c.D2Scaled[i] = nativeGTExp(w.DebugD2AfterRounds[i-1], beta)
			c.D1Scaled[i] = nativeGTExp(w.DebugD1AfterRounds[i-1], betaInv)
		}
		c.CPScaled[i] = nativeGTExp(sm.CPlus, alpha)
		c.CMScaled[i] = nativeGTExp(sm.CMinus, alphaInv)

		c.D1LScaled[i] = nativeGTExp(fm.D1Left, alpha)
		c.D1LSSetup[i] = nativeGTExp(w.Setup.Delta1L[round], alphaBeta)
		c.D1RSSetup[i] = nativeGTExp(w.Setup.Delta1R[round], beta)

		c.D2LScaled[i] = nativeGTExp(fm.D2Left, alphaInv)
		c.D2LSSetup[i] = nativeGTExp(w.Setup.Delta2L[round], alphaInvBetaInv)
		c.D2RSSetup[i] = nativeGTExp(w.Setup.Delta2R[round], betaInv)

		{
			var e1b, e1p, e1m bn254.G1Affine
			e1b.X.SetBigInt(hexToBigInt(fm.E1Beta.X))
			e1b.Y.SetBigInt(hexToBigInt(fm.E1Beta.Y))
			e1b.ScalarMultiplication(&e1b, beta)

			e1p.X.SetBigInt(hexToBigInt(sm.E1Plus.X))
			e1p.Y.SetBigInt(hexToBigInt(sm.E1Plus.Y))
			e1p.ScalarMultiplication(&e1p, alpha)

			e1m.X.SetBigInt(hexToBigInt(sm.E1Minus.X))
			e1m.Y.SetBigInt(hexToBigInt(sm.E1Minus.Y))
			e1m.ScalarMultiplication(&e1m, alphaInv)

			accumE1.Add(&accumE1, &e1b)
			accumE1.Add(&accumE1, &e1p)
			accumE1.Add(&accumE1, &e1m)
		}

		c.CheckpointC[i] = parseGT(w.DebugCAfterRounds[i])
		c.CheckpointD1[i] = parseGT(w.DebugD1AfterRounds[i])
		c.CheckpointD2[i] = parseGT(w.DebugD2AfterRounds[i])
	}

	c.AccumE1 = sw_bn254.NewG1Affine(accumE1)
	c.FinalE1 = parseG1(w.FinalE1)
	c.FinalP1G2 = parseG2(w.FinalP1G2)
	c.FinalP2G2 = parseG2(w.FinalP2G2)

	d := hexToBigInt(w.D)
	dInv := new(big.Int).ModInverse(d, r)
	dSq := new(big.Int).Mul(d, d)
	dSq.Mod(dSq, r)

	s1Acc := big.NewInt(1)
	s2Acc := big.NewInt(1)
	for roundIdx := 0; roundIdx < NumRounds9; roundIdx++ {
		coordIdx := NumRounds9 - 1 - roundIdx
		alpha := hexToBigInt(w.Alpha[roundIdx])
		alphaInv := new(big.Int).ModInverse(alpha, r)
		y := hexToBigInt(w.S1Coords[coordIdx])
		x := hexToBigInt(w.S2Coords[coordIdx])
		oneMinusY := new(big.Int).Sub(big.NewInt(1), y)
		oneMinusY.Mod(oneMinusY, r)
		oneMinusX := new(big.Int).Sub(big.NewInt(1), x)
		oneMinusX.Mod(oneMinusX, r)
		s1Factor := new(big.Int).Mul(alpha, oneMinusY)
		s1Factor.Add(s1Factor, y)
		s1Factor.Mod(s1Factor, r)
		s2Factor := new(big.Int).Mul(alphaInv, oneMinusX)
		s2Factor.Add(s2Factor, x)
		s2Factor.Mod(s2Factor, r)
		s1Acc.Mul(s1Acc, s1Factor)
		s1Acc.Mod(s1Acc, r)
		s2Acc.Mul(s2Acc, s2Factor)
		s2Acc.Mod(s2Acc, r)
	}
	sProduct := new(big.Int).Mul(s1Acc, s2Acc)
	sProduct.Mod(sProduct, r)
	c.SProduct = emulated.ValueOf[sw_bn254.ScalarField](sProduct)

	lastRoundIdx := NumRounds9 - 1
	c.HTScaled = nativeGTExp(w.Setup.HT, sProduct)
	c.D2Final = nativeGTExp(w.DebugD2AfterRounds[lastRoundIdx], d)
	c.D1Final = nativeGTExp(w.DebugD1AfterRounds[lastRoundIdx], dInv)
	c.D2InitScaled = nativeGTExp(w.VMV_D2, dSq)

	for i := 0; i <= NumRounds9; i++ {
		c.SetupChi[i] = parseGT(w.Setup.Chi[i])
	}
	c.SetupG1_0 = parseG1(w.Setup.G1_0)
	c.SetupG2_0 = parseG2(w.Setup.G2_0)
	c.SetupH1 = parseG1(w.Setup.H1)
	c.SetupH2 = parseG2(w.Setup.H2)

	// Compute InputHash = MiMC(packed values)
	mimcH := mimcbn254.NewMiMC()
	mask64 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	shift64 := new(big.Int).Lsh(big.NewInt(1), 64)

	writeScalar := func(v *big.Int) {
		var frEl fr.Element
		frEl.SetBigInt(v)
		b := frEl.Marshal()
		mimcH.Write(b)
	}

	writeFpPacked := func(v *big.Int) {
		limb0 := new(big.Int).And(v, mask64)
		limb1 := new(big.Int).And(new(big.Int).Rsh(v, 64), mask64)
		limb2 := new(big.Int).And(new(big.Int).Rsh(v, 128), mask64)
		limb3 := new(big.Int).And(new(big.Int).Rsh(v, 192), mask64)
		lo := new(big.Int).Add(limb0, new(big.Int).Mul(limb1, shift64))
		hi := new(big.Int).Add(limb2, new(big.Int).Mul(limb3, shift64))
		var loFr, hiFr fr.Element
		loFr.SetBigInt(lo)
		hiFr.SetBigInt(hi)
		mimcH.Write(loFr.Marshal())
		mimcH.Write(hiFr.Marshal())
	}

	for i := 0; i < NumRounds9; i++ {
		writeScalar(hexToBigInt(w.Alpha[i]))
	}
	for i := 0; i < NumRounds9; i++ {
		writeScalar(hexToBigInt(w.Beta[i]))
	}
	writeScalar(hexToBigInt(w.Gamma))
	writeScalar(hexToBigInt(w.D))
	for i := 0; i < NumRounds9; i++ {
		writeScalar(hexToBigInt(w.S1Coords[i]))
	}
	for i := 0; i < NumRounds9; i++ {
		writeScalar(hexToBigInt(w.S2Coords[i]))
	}
	commitGT := nativeGTFromJSON(w.Commitment)
	nine := new(fp.Element).SetUint64(9)
	karabina := func(a0, a1 *fp.Element) *big.Int {
		var t, res fp.Element
		t.Mul(nine, a1)
		res.Sub(a0, &t)
		var b big.Int
		res.BigInt(&b)
		return &b
	}
	fpToBig := func(v *fp.Element) *big.Int {
		var b big.Int
		v.BigInt(&b)
		return &b
	}
	commitFpBigs := []*big.Int{
		karabina(&commitGT.C0.B0.A0, &commitGT.C0.B0.A1),
		karabina(&commitGT.C1.B0.A0, &commitGT.C1.B0.A1),
		karabina(&commitGT.C0.B1.A0, &commitGT.C0.B1.A1),
		karabina(&commitGT.C1.B1.A0, &commitGT.C1.B1.A1),
		karabina(&commitGT.C0.B2.A0, &commitGT.C0.B2.A1),
		karabina(&commitGT.C1.B2.A0, &commitGT.C1.B2.A1),
		fpToBig(&commitGT.C0.B0.A1),
		fpToBig(&commitGT.C1.B0.A1),
		fpToBig(&commitGT.C0.B1.A1),
		fpToBig(&commitGT.C1.B1.A1),
		fpToBig(&commitGT.C0.B2.A1),
		fpToBig(&commitGT.C1.B2.A1),
	}
	for _, fpBig := range commitFpBigs {
		writeFpPacked(fpBig)
	}
	writeScalar(hexToBigInt(w.Evaluation))
	writeScalar(sProduct)

	inputHashBytes := mimcH.Sum(nil)
	var inputHashFr fr.Element
	inputHashFr.SetBytes(inputHashBytes)
	var inputHashBig big.Int
	inputHashFr.BigInt(&inputHashBig)
	c.InputHash = inputHashBig

	return &c, nil
}
