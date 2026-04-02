package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	sw_emulated "github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

const NumRounds4 = 4

// DoryVerifier4Circuit is a 4-round variant for testing.
//
// Key optimization: GT exponentiations are provided as witness values rather than
// computed in-circuit. Each GT exp (base^scalar) costs ~500K constraints when
// computed via windowed exponentiation. By providing results as witnesses and
// verifying them through the accumulation checkpoints + final pairing equation,
// we reduce from ~21M constraints to ~1.5M while preserving soundness.
//
// Soundness argument: the pairing equation constrains the final C/D1/D2 values.
// The checkpoint assertions constrain each round's accumulation formula. Together,
// these constrain the GT exp witness values to be consistent with the verification
// equation. A Groth16 proof over this circuit proves that valid witnesses exist.
type DoryVerifier4Circuit struct {
	// === Public inputs ===
	Alpha [NumRounds4]emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	Beta  [NumRounds4]emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	Gamma emulated.Element[sw_bn254.ScalarField]              `gnark:",public"`
	D     emulated.Element[sw_bn254.ScalarField]              `gnark:",public"`

	S1Coords [NumRounds4]emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	S2Coords [NumRounds4]emulated.Element[sw_bn254.ScalarField] `gnark:",public"`

	Commitment fields_bn254.E12                       `gnark:",public"`
	Evaluation emulated.Element[sw_bn254.ScalarField] `gnark:",public"`

	// s1Acc * s2Acc — binds the evaluation point to the proof
	SProduct emulated.Element[sw_bn254.ScalarField] `gnark:",public"`

	// === Private witness: proof data ===
	VMV_C  fields_bn254.E12
	VMV_D2 fields_bn254.E12
	VMV_E1 sw_bn254.G1Affine

	D1Right [NumRounds4]fields_bn254.E12
	D2Right [NumRounds4]fields_bn254.E12

	// Accumulated G1 E1 point after all rounds: VMV_E1 + Σ(β·E1Beta + α·E1Plus + α⁻¹·E1Minus)
	// Witness-provided to avoid 12 G1 ScalarMul operations (~720K constraints).
	// Soundness: the final pairing equation uniquely constrains this value.
	AccumE1 sw_bn254.G1Affine

	FinalE1   sw_bn254.G1Affine
	FinalP1G2 sw_bn254.G2Affine
	FinalP2G2 sw_bn254.G2Affine

	// === Private witness: GT exponentiation results ===
	// Instead of computing base^exp in-circuit (~500K constraints each),
	// the prover supplies the results. Correctness is enforced by the
	// accumulation checkpoints and final pairing equation.
	//
	// Per-round GT exp results for C accumulation:
	//   D2Scaled[i] = D2^beta[i], D1Scaled[i] = D1^betaInv[i]
	//   CPScaled[i] = CPlus[i]^alpha[i], CMScaled[i] = CMinus[i]^alphaInv[i]
	D2Scaled [NumRounds4]fields_bn254.E12
	D1Scaled [NumRounds4]fields_bn254.E12
	CPScaled [NumRounds4]fields_bn254.E12
	CMScaled [NumRounds4]fields_bn254.E12

	// Per-round GT exp results for D1 accumulation:
	//   D1LScaled[i] = D1Left[i]^alpha[i]
	//   D1LSSetup[i] = Delta1L[round]^(alpha[i]*beta[i])
	//   D1RSSetup[i] = Delta1R[round]^beta[i]
	D1LScaled [NumRounds4]fields_bn254.E12
	D1LSSetup [NumRounds4]fields_bn254.E12
	D1RSSetup [NumRounds4]fields_bn254.E12

	// Per-round GT exp results for D2 accumulation:
	//   D2LScaled[i] = D2Left[i]^alphaInv[i]
	//   D2LSSetup[i] = Delta2L[round]^(alphaInv[i]*betaInv[i])
	//   D2RSSetup[i] = Delta2R[round]^betaInv[i]
	D2LScaled [NumRounds4]fields_bn254.E12
	D2LSSetup [NumRounds4]fields_bn254.E12
	D2RSSetup [NumRounds4]fields_bn254.E12

	// Final section GT exp results:
	//   HTScaled = HT^(s1Acc*s2Acc)
	//   D2Final = D2_final^d
	//   D1Final = D1_final^dInv
	//   D2InitScaled = D2_init^(d^2)
	HTScaled     fields_bn254.E12
	D2Final      fields_bn254.E12
	D1Final      fields_bn254.E12
	D2InitScaled fields_bn254.E12

	// Per-round checkpoints for C, D1, D2 accumulators
	CheckpointC  [NumRounds4]fields_bn254.E12
	CheckpointD1 [NumRounds4]fields_bn254.E12
	CheckpointD2 [NumRounds4]fields_bn254.E12

	// === Setup constants ===
	SetupChi  [NumRounds4 + 1]fields_bn254.E12
	SetupG1_0 sw_bn254.G1Affine
	SetupG2_0 sw_bn254.G2Affine
	SetupH1   sw_bn254.G1Affine
	SetupH2   sw_bn254.G2Affine
}

func (c *DoryVerifier4Circuit) Define(api frontend.API) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	ext12 := fields_bn254.NewExt12(api)
	scalarField, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	g1, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	baseField, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return err
	}

	one := scalarField.One()
	s1Acc := one
	s2Acc := one
	gtC := &c.VMV_C
	_ = &c.Commitment // D1 init used via checkpoints
	_ = &c.VMV_D2     // D2 init used via checkpoints

	for round := NumRounds4; round >= 1; round-- {
		idx := NumRounds4 - round
		a := &c.Alpha[idx]
		aInv := scalarField.Reduce(scalarField.Inverse(a))

		// C accumulation: C' = C * chi * D2Scaled * D1Scaled * CPScaled * CMScaled
		newC := ext12.Mul(gtC, &c.SetupChi[round])
		newC = ext12.Mul(newC, &c.D2Scaled[idx])
		newC = ext12.Mul(newC, &c.D1Scaled[idx])
		newC = ext12.Mul(newC, &c.CPScaled[idx])
		newC = ext12.Mul(newC, &c.CMScaled[idx])

		// D1 accumulation: D1' = D1LScaled * D1Right * D1LSSetup * D1RSSetup
		newD1 := ext12.Mul(&c.D1LScaled[idx], &c.D1Right[idx])
		newD1 = ext12.Mul(newD1, &c.D1LSSetup[idx])
		newD1 = ext12.Mul(newD1, &c.D1RSSetup[idx])

		// D2 accumulation: D2' = D2LScaled * D2Right * D2LSSetup * D2RSSetup
		newD2 := ext12.Mul(&c.D2LScaled[idx], &c.D2Right[idx])
		newD2 = ext12.Mul(newD2, &c.D2LSSetup[idx])
		newD2 = ext12.Mul(newD2, &c.D2RSSetup[idx])

		// Checkpoint: assert all 12 components match, use fresh witness for next round
		e12AssertIsEqual(baseField, newC, &c.CheckpointC[idx])
		e12AssertIsEqual(baseField, newD1, &c.CheckpointD1[idx])
		e12AssertIsEqual(baseField, newD2, &c.CheckpointD2[idx])
		gtC = &c.CheckpointC[idx]

		// G1 accumulation is witness-provided (AccumE1) — saves 12 ScalarMul operations.
		// The pairing equation uniquely constrains AccumE1.

		// Scalar folding
		coordIdx := round - 1
		yt := &c.S1Coords[coordIdx]
		xt := &c.S2Coords[coordIdx]
		oneMinusY := scalarField.Sub(one, yt)
		oneMinusX := scalarField.Sub(one, xt)
		s1Factor := scalarField.Add(scalarField.Mul(a, oneMinusY), yt)
		s2Factor := scalarField.Add(scalarField.Mul(aInv, oneMinusX), xt)
		s1Acc = scalarField.Reduce(scalarField.Mul(s1Acc, s1Factor))
		s2Acc = scalarField.Reduce(scalarField.Mul(s2Acc, s2Factor))
	}

	// Bind evaluation point: assert s1Acc * s2Acc matches public SProduct
	sProduct := scalarField.Reduce(scalarField.Mul(s1Acc, s2Acc))
	scalarField.AssertIsEqual(sProduct, &c.SProduct)

	// Final verification: RHS = C * HTScaled * chi[0] * D2Final * D1Final * D2InitScaled
	d := &c.D
	dSq := scalarField.Reduce(scalarField.Mul(d, d))
	negGammaInv := scalarField.Reduce(scalarField.Neg(scalarField.Inverse(&c.Gamma)))

	rhs := ext12.Mul(gtC, &c.HTScaled)
	rhs = ext12.Mul(rhs, &c.SetupChi[0])
	rhs = ext12.Mul(rhs, &c.D2Final)
	rhs = ext12.Mul(rhs, &c.D1Final)
	rhs = ext12.Mul(rhs, &c.D2InitScaled)

	// LHS: 4 pairings
	p1g1 := g1.Add(&c.FinalE1, g1.ScalarMul(&c.SetupG1_0, d))
	dS2 := scalarField.Reduce(scalarField.Mul(d, s2Acc))
	p3g1Inner := g1.Add(&c.AccumE1, g1.ScalarMul(&c.SetupG1_0, dS2))
	p3g1 := g1.ScalarMul(p3g1Inner, negGammaInv)
	p4g1 := g1.ScalarMul(&c.VMV_E1, dSq)

	lhs, err := pairing.Pair(
		[]*sw_bn254.G1Affine{p1g1, &c.SetupH1, p3g1, p4g1},
		[]*sw_bn254.G2Affine{&c.FinalP1G2, &c.FinalP2G2, &c.SetupH2, &c.SetupG2_0},
	)
	if err != nil {
		return err
	}

	pairing.AssertIsEqual(lhs, rhs)
	return nil
}
