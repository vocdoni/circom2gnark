package main

import (
	"fmt"
	"math/big"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	cmimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
)

func ComputePublicInputsHashFromBLS12377ToBW6761(publicInputs [][]emulated.Element[sw_bls12377.ScalarField]) (*big.Int, error) {
	h := cmimc.NewMiMC()
	var buf [fr_bls12377.Bytes]byte
	for _, inputs := range publicInputs {
		for _, input := range inputs {
			// Hash each limb of the emulated element
			for _, limb := range input.Limbs {
				limbValue, err := getBigIntFromVariable(limb)
				if err != nil {
					return nil, err
				}
				limbValue.FillBytes(buf[:])
				h.Write(buf[:])
			}
		}
	}
	digest := h.Sum(nil)
	publicHash := new(big.Int).SetBytes(digest)

	return publicHash, nil
}

func getBigIntFromVariable(v frontend.Variable) (*big.Int, error) {
	switch val := v.(type) {
	case *big.Int:
		return val, nil
	case big.Int:
		return &val, nil
	case uint64:
		return new(big.Int).SetUint64(val), nil
	case int:
		return big.NewInt(int64(val)), nil
	case string:
		bi := new(big.Int)
		_, ok := bi.SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid string for big.Int: %s", val)
		}
		return bi, nil
	default:
		return nil, fmt.Errorf("unsupported variable type %T", val)
	}
}
