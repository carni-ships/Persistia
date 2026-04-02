package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

func TestGTIdentity(t *testing.T) {
	// gnark circuit identity via NewGTEl
	var one bn254.GT
	one.SetOne()

	t.Logf("Native GT.C0.B0.A0 = %s", one.C0.B0.A0.String())
	t.Logf("Native GT.C0.B0.A1 = %s", one.C0.B0.A1.String())
	t.Logf("Native GT.C0.B1.A0 = %s", one.C0.B1.A0.String())
	t.Logf("Native GT.C1.B0.A0 = %s", one.C1.B0.A0.String())

	gnarkOne := sw_bn254.NewGTEl(one)

	// Check what NewGTEl(1) looks like
	t.Logf("NewGTEl(1).A0 = %v", gnarkOne.A0.Limbs)
	t.Logf("NewGTEl(1).A1 = %v", gnarkOne.A1.Limbs)
	t.Logf("NewGTEl(1).A2 = %v", gnarkOne.A2.Limbs)
	t.Logf("NewGTEl(1).A3 = %v", gnarkOne.A3.Limbs)
	t.Logf("NewGTEl(1).A4 = %v", gnarkOne.A4.Limbs)
	t.Logf("NewGTEl(1).A5 = %v", gnarkOne.A5.Limbs)
	t.Logf("NewGTEl(1).A6 = %v", gnarkOne.A6.Limbs)
	t.Logf("NewGTEl(1).A7 = %v", gnarkOne.A7.Limbs)
	t.Logf("NewGTEl(1).A8 = %v", gnarkOne.A8.Limbs)
	t.Logf("NewGTEl(1).A9 = %v", gnarkOne.A9.Limbs)
	t.Logf("NewGTEl(1).A10 = %v", gnarkOne.A10.Limbs)
	t.Logf("NewGTEl(1).A11 = %v", gnarkOne.A11.Limbs)

	// Ext12.One() in gnark circuit returns {A0:1, A1:0, ..., A11:0}
	// Let's check if NewGTEl(1) also has that form
	allZero := true
	for _, l := range gnarkOne.A1.Limbs {
		if l != 0 {
			allZero = false
		}
	}
	if allZero {
		t.Log("A1 is zero — NewGTEl identity matches simple form")
	} else {
		t.Log("A1 is NON-ZERO — NewGTEl identity does NOT match ext12.One()!")
		t.Log("THIS IS THE BUG: ext12.One() != NewGTEl(GT.SetOne())")
	}
}
