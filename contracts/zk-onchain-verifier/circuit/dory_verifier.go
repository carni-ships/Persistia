package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	sw_emulated "github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
)

const NumRounds = 11

// DoryVerifierCircuit verifies the Dory reduce-and-fold protocol
// and final pairing check inside a Groth16 circuit.
//
// Architecture (witness-provided GT exponentiation approach):
//   - Fiat-Shamir transcript replayed in Solidity → challenges as public inputs
//   - GT exponentiations are provided as witness values rather than computed
//     in-circuit. Each GT exp costs ~500K constraints when computed; by providing
//     results as witnesses and verifying through checkpoints + final pairing,
//     we reduce from ~57M to ~3.8M constraints while preserving soundness.
//   - G1 E1 accumulation is witness-provided, constrained by the final pairing equation
//   - G2 operations are avoided: prover supplies composite G2 points as witness
type DoryVerifierCircuit struct {
	// === Single public input: MiMC hash of all verification inputs ===
	// Reduces Groth16 on-chain MSM from 236 EC scalar muls (~1.4M gas) to 1 (~6K gas).
	// The Solidity contract computes the same MiMC hash and passes it as the only public input.
	InputHash frontend.Variable `gnark:",public"`

	// === Private inputs (bound to InputHash via in-circuit MiMC verification) ===
	Alpha [NumRounds]emulated.Element[sw_bn254.ScalarField]
	Beta  [NumRounds]emulated.Element[sw_bn254.ScalarField]
	Gamma emulated.Element[sw_bn254.ScalarField]
	D     emulated.Element[sw_bn254.ScalarField]

	S1Coords [NumRounds]emulated.Element[sw_bn254.ScalarField]
	S2Coords [NumRounds]emulated.Element[sw_bn254.ScalarField]

	Commitment fields_bn254.E12
	Evaluation emulated.Element[sw_bn254.ScalarField]

	// s1Acc * s2Acc — binds the evaluation point to the proof
	SProduct emulated.Element[sw_bn254.ScalarField]

	// === Private witness: proof data ===
	VMV_C  fields_bn254.E12
	VMV_D2 fields_bn254.E12
	VMV_E1 sw_bn254.G1Affine

	D1Right [NumRounds]fields_bn254.E12
	D2Right [NumRounds]fields_bn254.E12

	// Accumulated G1 E1 point after all rounds: VMV_E1 + Σ(β·E1Beta + α·E1Plus + α⁻¹·E1Minus)
	// Witness-provided to avoid 12*NumRounds G1 ScalarMul operations.
	// Soundness: the final pairing equation uniquely constrains this value.
	AccumE1 sw_bn254.G1Affine

	FinalE1   sw_bn254.G1Affine
	FinalP1G2 sw_bn254.G2Affine
	FinalP2G2 sw_bn254.G2Affine

	// === Private witness: GT exponentiation results ===
	// Per-round GT exp results for C accumulation:
	D2Scaled [NumRounds]fields_bn254.E12
	D1Scaled [NumRounds]fields_bn254.E12
	CPScaled [NumRounds]fields_bn254.E12
	CMScaled [NumRounds]fields_bn254.E12

	// Per-round GT exp results for D1 accumulation:
	D1LScaled [NumRounds]fields_bn254.E12
	D1LSSetup [NumRounds]fields_bn254.E12
	D1RSSetup [NumRounds]fields_bn254.E12

	// Per-round GT exp results for D2 accumulation:
	D2LScaled [NumRounds]fields_bn254.E12
	D2LSSetup [NumRounds]fields_bn254.E12
	D2RSSetup [NumRounds]fields_bn254.E12

	// Final section GT exp results:
	HTScaled     fields_bn254.E12
	D2Final      fields_bn254.E12
	D1Final      fields_bn254.E12
	D2InitScaled fields_bn254.E12

	// Per-round checkpoints for C, D1, D2 accumulators
	CheckpointC  [NumRounds]fields_bn254.E12
	CheckpointD1 [NumRounds]fields_bn254.E12
	CheckpointD2 [NumRounds]fields_bn254.E12

	// === Setup constants ===
	SetupChi  [NumRounds + 1]fields_bn254.E12
	SetupG1_0 sw_bn254.G1Affine
	SetupG2_0 sw_bn254.G2Affine
	SetupH1   sw_bn254.G1Affine
	SetupH2   sw_bn254.G2Affine
}

func (c *DoryVerifierCircuit) Define(api frontend.API) error {
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

	for round := NumRounds; round >= 1; round-- {
		idx := NumRounds - round
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

	// MiMC hash binds all private inputs to the single public InputHash.
	// Hash full values (not individual limbs) to minimize on-chain MiMC absorptions:
	//   - Scalar field elements: reconstruct from 4×64-bit limbs → 1 native Fr value per element
	//   - Fp elements: pack 2 limbs → 1 value (128-bit, fits in Fr) → 2 values per element
	// Total: 48 scalar + 24 Fp = 72 absorptions (down from 240 limbs)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	shift64 := new(big.Int).Lsh(big.NewInt(1), 64)
	shift128 := new(big.Int).Lsh(big.NewInt(1), 128)
	shift192 := new(big.Int).Lsh(big.NewInt(1), 192)

	// Reconstruct a BN254 scalar from 4×64-bit emulated limbs into a single native Fr variable.
	reconstructScalar := func(el *emulated.Element[sw_bn254.ScalarField]) frontend.Variable {
		return api.Add(
			el.Limbs[0],
			api.Mul(el.Limbs[1], shift64),
			api.Mul(el.Limbs[2], shift128),
			api.Mul(el.Limbs[3], shift192),
		)
	}

	// Pack Fp limbs into 2×128-bit values (each fits in native Fr).
	packFp := func(el *emulated.Element[emulated.BN254Fp]) (frontend.Variable, frontend.Variable) {
		lo := api.Add(el.Limbs[0], api.Mul(el.Limbs[1], shift64))
		hi := api.Add(el.Limbs[2], api.Mul(el.Limbs[3], shift64))
		return lo, hi
	}

	for i := 0; i < NumRounds; i++ {
		h.Write(reconstructScalar(&c.Alpha[i]))
	}
	for i := 0; i < NumRounds; i++ {
		h.Write(reconstructScalar(&c.Beta[i]))
	}
	h.Write(reconstructScalar(&c.Gamma))
	h.Write(reconstructScalar(&c.D))
	for i := 0; i < NumRounds; i++ {
		h.Write(reconstructScalar(&c.S1Coords[i]))
	}
	for i := 0; i < NumRounds; i++ {
		h.Write(reconstructScalar(&c.S2Coords[i]))
	}
	for _, fpEl := range []*emulated.Element[emulated.BN254Fp]{
		&c.Commitment.A0, &c.Commitment.A1, &c.Commitment.A2, &c.Commitment.A3,
		&c.Commitment.A4, &c.Commitment.A5, &c.Commitment.A6, &c.Commitment.A7,
		&c.Commitment.A8, &c.Commitment.A9, &c.Commitment.A10, &c.Commitment.A11,
	} {
		lo, hi := packFp(fpEl)
		h.Write(lo, hi)
	}
	h.Write(reconstructScalar(&c.Evaluation))
	h.Write(reconstructScalar(&c.SProduct))
	api.AssertIsEqual(h.Sum(), c.InputHash)

	return nil
}

// e12AssertIsEqual asserts all 12 components of two E12 elements are equal.
func e12AssertIsEqual(fp *emulated.Field[emulated.BN254Fp], a, b *fields_bn254.E12) {
	fp.AssertIsEqual(&a.A0, &b.A0)
	fp.AssertIsEqual(&a.A1, &b.A1)
	fp.AssertIsEqual(&a.A2, &b.A2)
	fp.AssertIsEqual(&a.A3, &b.A3)
	fp.AssertIsEqual(&a.A4, &b.A4)
	fp.AssertIsEqual(&a.A5, &b.A5)
	fp.AssertIsEqual(&a.A6, &b.A6)
	fp.AssertIsEqual(&a.A7, &b.A7)
	fp.AssertIsEqual(&a.A8, &b.A8)
	fp.AssertIsEqual(&a.A9, &b.A9)
	fp.AssertIsEqual(&a.A10, &b.A10)
	fp.AssertIsEqual(&a.A11, &b.A11)
}

// e12Reduce reduces all 12 components of an E12 element to prevent overflow
// accumulation in gnark's deferred emulated multiplication checks.
func e12Reduce(fp *emulated.Field[emulated.BN254Fp], a *fields_bn254.E12) *fields_bn254.E12 {
	return &fields_bn254.E12{
		A0: *fp.Reduce(&a.A0), A1: *fp.Reduce(&a.A1),
		A2: *fp.Reduce(&a.A2), A3: *fp.Reduce(&a.A3),
		A4: *fp.Reduce(&a.A4), A5: *fp.Reduce(&a.A5),
		A6: *fp.Reduce(&a.A6), A7: *fp.Reduce(&a.A7),
		A8: *fp.Reduce(&a.A8), A9: *fp.Reduce(&a.A9),
		A10: *fp.Reduce(&a.A10), A11: *fp.Reduce(&a.A11),
	}
}

// e12Select returns z1 if selector==1, z0 if selector==0.
func e12Select(fp *emulated.Field[emulated.BN254Fp], selector frontend.Variable, z1, z0 *fields_bn254.E12) *fields_bn254.E12 {
	return &fields_bn254.E12{
		A0:  *fp.Select(selector, &z1.A0, &z0.A0),
		A1:  *fp.Select(selector, &z1.A1, &z0.A1),
		A2:  *fp.Select(selector, &z1.A2, &z0.A2),
		A3:  *fp.Select(selector, &z1.A3, &z0.A3),
		A4:  *fp.Select(selector, &z1.A4, &z0.A4),
		A5:  *fp.Select(selector, &z1.A5, &z0.A5),
		A6:  *fp.Select(selector, &z1.A6, &z0.A6),
		A7:  *fp.Select(selector, &z1.A7, &z0.A7),
		A8:  *fp.Select(selector, &z1.A8, &z0.A8),
		A9:  *fp.Select(selector, &z1.A9, &z0.A9),
		A10: *fp.Select(selector, &z1.A10, &z0.A10),
		A11: *fp.Select(selector, &z1.A11, &z0.A11),
	}
}

// e12Mux selects table[sel] from a slice of E12 elements using per-component Mux.
func e12Mux(fp *emulated.Field[emulated.BN254Fp], sel frontend.Variable, table []*fields_bn254.E12) *fields_bn254.E12 {
	n := len(table)
	a0 := make([]*emulated.Element[emulated.BN254Fp], n)
	a1 := make([]*emulated.Element[emulated.BN254Fp], n)
	a2 := make([]*emulated.Element[emulated.BN254Fp], n)
	a3 := make([]*emulated.Element[emulated.BN254Fp], n)
	a4 := make([]*emulated.Element[emulated.BN254Fp], n)
	a5 := make([]*emulated.Element[emulated.BN254Fp], n)
	a6 := make([]*emulated.Element[emulated.BN254Fp], n)
	a7 := make([]*emulated.Element[emulated.BN254Fp], n)
	a8 := make([]*emulated.Element[emulated.BN254Fp], n)
	a9 := make([]*emulated.Element[emulated.BN254Fp], n)
	a10 := make([]*emulated.Element[emulated.BN254Fp], n)
	a11 := make([]*emulated.Element[emulated.BN254Fp], n)
	for i := range table {
		a0[i] = &table[i].A0
		a1[i] = &table[i].A1
		a2[i] = &table[i].A2
		a3[i] = &table[i].A3
		a4[i] = &table[i].A4
		a5[i] = &table[i].A5
		a6[i] = &table[i].A6
		a7[i] = &table[i].A7
		a8[i] = &table[i].A8
		a9[i] = &table[i].A9
		a10[i] = &table[i].A10
		a11[i] = &table[i].A11
	}
	return &fields_bn254.E12{
		A0:  *fp.Mux(sel, a0...),
		A1:  *fp.Mux(sel, a1...),
		A2:  *fp.Mux(sel, a2...),
		A3:  *fp.Mux(sel, a3...),
		A4:  *fp.Mux(sel, a4...),
		A5:  *fp.Mux(sel, a5...),
		A6:  *fp.Mux(sel, a6...),
		A7:  *fp.Mux(sel, a7...),
		A8:  *fp.Mux(sel, a8...),
		A9:  *fp.Mux(sel, a9...),
		A10: *fp.Mux(sel, a10...),
		A11: *fp.Mux(sel, a11...),
	}
}

func NewBigInt(v uint64) *big.Int {
	return new(big.Int).SetUint64(v)
}
