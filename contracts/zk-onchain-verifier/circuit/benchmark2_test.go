package circuit

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// Window2GTExpCircuit uses 2-bit windowed exponentiation.
type Window2GTExpCircuit struct {
	Base   fields_bn254.E12                       `gnark:",public"`
	Scalar emulated.Element[sw_bn254.ScalarField] `gnark:",public"`
	Result fields_bn254.E12                       `gnark:",public"`
}

func (c *Window2GTExpCircuit) Define(api frontend.API) error {
	ext12 := fields_bn254.NewExt12(api)
	scalarField, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	baseField, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return err
	}

	bits := scalarField.ToBits(&c.Scalar)
	const windowSize = 2
	const tableSize = 4

	table := make([]*fields_bn254.E12, tableSize)
	table[0] = ext12.One()
	table[1] = &c.Base
	table[2] = ext12.Mul(&c.Base, &c.Base)
	table[3] = ext12.Mul(table[2], &c.Base)

	for len(bits)%windowSize != 0 {
		bits = append(bits, 0)
	}

	result := ext12.One()
	nWindows := len(bits) / windowSize
	for w := nWindows - 1; w >= 0; w-- {
		if w < nWindows-1 {
			result = ext12.Square(result)
			result = ext12.Square(result)
		}
		bitOffset := w * windowSize
		windowIdx := api.Add(bits[bitOffset], api.Mul(bits[bitOffset+1], 2))
		selected := e12Mux(baseField, windowIdx, table)
		result = ext12.Mul(result, selected)
	}

	baseField.AssertIsEqual(&result.A0, &c.Result.A0)
	return nil
}

func TestWindow2GTExpConstraintCount(t *testing.T) {
	var circuit Window2GTExpCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}
	fmt.Printf("GT exp 2-bit window (1 call): %d constraints\n", cs.GetNbConstraints())
}
