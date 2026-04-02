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

const NumRounds9 = 9

// DoryVerifier9Circuit is a 9-round variant matching sha3 production traces.
// Uses MiMC-hashed single public InputHash (same architecture as 11-round).
type DoryVerifier9Circuit struct {
	InputHash frontend.Variable `gnark:",public"`

	Alpha [NumRounds9]emulated.Element[sw_bn254.ScalarField]
	Beta  [NumRounds9]emulated.Element[sw_bn254.ScalarField]
	Gamma emulated.Element[sw_bn254.ScalarField]
	D     emulated.Element[sw_bn254.ScalarField]

	S1Coords [NumRounds9]emulated.Element[sw_bn254.ScalarField]
	S2Coords [NumRounds9]emulated.Element[sw_bn254.ScalarField]

	Commitment fields_bn254.E12
	Evaluation emulated.Element[sw_bn254.ScalarField]
	SProduct   emulated.Element[sw_bn254.ScalarField]

	VMV_C  fields_bn254.E12
	VMV_D2 fields_bn254.E12
	VMV_E1 sw_bn254.G1Affine

	D1Right [NumRounds9]fields_bn254.E12
	D2Right [NumRounds9]fields_bn254.E12

	AccumE1   sw_bn254.G1Affine
	FinalE1   sw_bn254.G1Affine
	FinalP1G2 sw_bn254.G2Affine
	FinalP2G2 sw_bn254.G2Affine

	D2Scaled [NumRounds9]fields_bn254.E12
	D1Scaled [NumRounds9]fields_bn254.E12
	CPScaled [NumRounds9]fields_bn254.E12
	CMScaled [NumRounds9]fields_bn254.E12

	D1LScaled [NumRounds9]fields_bn254.E12
	D1LSSetup [NumRounds9]fields_bn254.E12
	D1RSSetup [NumRounds9]fields_bn254.E12

	D2LScaled [NumRounds9]fields_bn254.E12
	D2LSSetup [NumRounds9]fields_bn254.E12
	D2RSSetup [NumRounds9]fields_bn254.E12

	HTScaled     fields_bn254.E12
	D2Final      fields_bn254.E12
	D1Final      fields_bn254.E12
	D2InitScaled fields_bn254.E12

	CheckpointC  [NumRounds9]fields_bn254.E12
	CheckpointD1 [NumRounds9]fields_bn254.E12
	CheckpointD2 [NumRounds9]fields_bn254.E12

	SetupChi  [NumRounds9 + 1]fields_bn254.E12
	SetupG1_0 sw_bn254.G1Affine
	SetupG2_0 sw_bn254.G2Affine
	SetupH1   sw_bn254.G1Affine
	SetupH2   sw_bn254.G2Affine
}

func (c *DoryVerifier9Circuit) Define(api frontend.API) error {
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

	for round := NumRounds9; round >= 1; round-- {
		idx := NumRounds9 - round
		a := &c.Alpha[idx]
		aInv := scalarField.Reduce(scalarField.Inverse(a))

		newC := ext12.Mul(gtC, &c.SetupChi[round])
		newC = ext12.Mul(newC, &c.D2Scaled[idx])
		newC = ext12.Mul(newC, &c.D1Scaled[idx])
		newC = ext12.Mul(newC, &c.CPScaled[idx])
		newC = ext12.Mul(newC, &c.CMScaled[idx])

		newD1 := ext12.Mul(&c.D1LScaled[idx], &c.D1Right[idx])
		newD1 = ext12.Mul(newD1, &c.D1LSSetup[idx])
		newD1 = ext12.Mul(newD1, &c.D1RSSetup[idx])

		newD2 := ext12.Mul(&c.D2LScaled[idx], &c.D2Right[idx])
		newD2 = ext12.Mul(newD2, &c.D2LSSetup[idx])
		newD2 = ext12.Mul(newD2, &c.D2RSSetup[idx])

		e12AssertIsEqual(baseField, newC, &c.CheckpointC[idx])
		e12AssertIsEqual(baseField, newD1, &c.CheckpointD1[idx])
		e12AssertIsEqual(baseField, newD2, &c.CheckpointD2[idx])
		gtC = &c.CheckpointC[idx]

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

	sProduct := scalarField.Reduce(scalarField.Mul(s1Acc, s2Acc))
	scalarField.AssertIsEqual(sProduct, &c.SProduct)

	d := &c.D
	dSq := scalarField.Reduce(scalarField.Mul(d, d))
	negGammaInv := scalarField.Reduce(scalarField.Neg(scalarField.Inverse(&c.Gamma)))

	rhs := ext12.Mul(gtC, &c.HTScaled)
	rhs = ext12.Mul(rhs, &c.SetupChi[0])
	rhs = ext12.Mul(rhs, &c.D2Final)
	rhs = ext12.Mul(rhs, &c.D1Final)
	rhs = ext12.Mul(rhs, &c.D2InitScaled)

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

	// MiMC hash binding
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	shift64 := new(big.Int).Lsh(big.NewInt(1), 64)
	shift128 := new(big.Int).Lsh(big.NewInt(1), 128)
	shift192 := new(big.Int).Lsh(big.NewInt(1), 192)

	reconstructScalar := func(el *emulated.Element[sw_bn254.ScalarField]) frontend.Variable {
		return api.Add(
			el.Limbs[0],
			api.Mul(el.Limbs[1], shift64),
			api.Mul(el.Limbs[2], shift128),
			api.Mul(el.Limbs[3], shift192),
		)
	}

	packFp := func(el *emulated.Element[emulated.BN254Fp]) (frontend.Variable, frontend.Variable) {
		lo := api.Add(el.Limbs[0], api.Mul(el.Limbs[1], shift64))
		hi := api.Add(el.Limbs[2], api.Mul(el.Limbs[3], shift64))
		return lo, hi
	}

	for i := 0; i < NumRounds9; i++ {
		h.Write(reconstructScalar(&c.Alpha[i]))
	}
	for i := 0; i < NumRounds9; i++ {
		h.Write(reconstructScalar(&c.Beta[i]))
	}
	h.Write(reconstructScalar(&c.Gamma))
	h.Write(reconstructScalar(&c.D))
	for i := 0; i < NumRounds9; i++ {
		h.Write(reconstructScalar(&c.S1Coords[i]))
	}
	for i := 0; i < NumRounds9; i++ {
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
