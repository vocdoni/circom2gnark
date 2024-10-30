// Package parser provides functions to parse Circom/SnarkJS Groth16 proofs
// and verification keys and convert them into Gnark-compatible structures for verification.
package parser

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	// Import BN254 curve and field elements from gnark-crypto
	"github.com/consensys/gnark-crypto/ecc/bn254"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"

	// Import algebra types for BN254
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"

	// Import recursion package for VerifyingKey and Proof types
	recursion "github.com/consensys/gnark/std/recursion/groth16"

	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// ParseSnarkJSProof parses the JSON-encoded proof data into a SnarkJSProof struct.
func ParseSnarkJSProof(data []byte) (*SnarkJSProof, error) {
	var proof SnarkJSProof
	err := json.Unmarshal(data, &proof)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proof JSON: %v", err)
	}
	return &proof, nil
}

// ParseSnarkJSVerificationKey parses the JSON-encoded verification key data into a SnarkJSVerificationKey struct.
func ParseSnarkJSVerificationKey(data []byte) (*SnarkJSVerificationKey, error) {
	var vk SnarkJSVerificationKey
	err := json.Unmarshal(data, &vk)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verification key JSON: %v", err)
	}
	return &vk, nil
}

//nolint:gomnd
func stringToG1(h []string) (*curve.G1Affine, error) {
	if len(h) <= 2 {
		return nil, fmt.Errorf("not enough data for stringToG1")
	}
	h = h[:2]
	hexa := false
	if len(h[0]) > 1 {
		if "0x" == h[0][:2] {
			hexa = true
		}
	}
	in := ""

	var b []byte
	var err error
	if hexa {
		for i := range h {
			in += strings.TrimPrefix(h[i], "0x")
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		// TODO use stringToBytes()
		if h[0] == "1" {
			h[0] = "0"
		}
		if h[1] == "1" {
			h[1] = "0"
		}
		bi0, ok := new(big.Int).SetString(h[0], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		bi1, ok := new(big.Int).SetString(h[1], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		b0 := bi0.Bytes()
		b1 := bi1.Bytes()
		if len(b0) != 32 {
			b0 = addZPadding(b0)
		}
		if len(b1) != 32 {
			b1 = addZPadding(b1)
		}

		b = append(b, b0...)
		b = append(b, b1...)
	}
	p := new(curve.G1Affine)
	err = p.Unmarshal(b)

	return p, err
}

func stringToG2(h [][]string) (*curve.G2Affine, error) {
	if len(h) <= 2 { //nolint:gomnd
		return nil, fmt.Errorf("not enough data for stringToG2")
	}
	h = h[:2]
	hexa := false
	if len(h[0][0]) > 1 {
		if "0x" == h[0][0][:2] {
			hexa = true
		}
	}
	in := ""
	var b []byte
	var err error
	if hexa {
		for i := 0; i < len(h); i++ {
			for j := 0; j < len(h[i]); j++ {
				in += strings.TrimPrefix(h[i][j], "0x")
			}
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		bH, err := stringToBytes(h[0][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[0][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
	}

	p := new(curve.G2Affine)
	err = p.Unmarshal(b)
	return p, err
}

// ParsePublicInputs parses an array of strings representing public inputs into a slice of bn254fr.Element.
func ParsePublicInputs(publicSignals []string) ([]bn254fr.Element, error) {
	publicInputs := make([]bn254fr.Element, len(publicSignals))
	for i, s := range publicSignals {
		bi, err := stringToBigInt(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public input %d: %v", i, err)
		}
		publicInputs[i].SetBigInt(bi)
	}
	return publicInputs, nil
}

func ParsePublicInputsAsBigInt(publicSignals []string) ([]*big.Int, error) {
	publicInputs := []*big.Int{}
	for i, s := range publicSignals {
		bi, err := stringToBigInt(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public input %d: %v", i, err)
		}
		publicInputs = append(publicInputs, bi)
	}
	return publicInputs, nil
}

// ConvertProof converts a SnarkJSProof into a Gnark-compatible Proof structure.
func ConvertProof(snarkProof *SnarkJSProof) (*groth16_bn254.Proof, error) {
	// Parse PiA (G1 point)
	arG1, err := stringToG1(snarkProof.PiA)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiA: %v", err)
	}
	// Parse PiC (G1 point)
	krsG1, err := stringToG1(snarkProof.PiC)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiC: %v", err)
	}
	// Parse PiB (G2 point)
	bsG2, err := stringToG2(snarkProof.PiB)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiB: %v", err)
	}
	// Construct the Proof
	gnarkProof := &groth16_bn254.Proof{
		Ar:  *arG1,
		Krs: *krsG1,
		Bs:  *bsG2,
		// Assuming no commitments
	}
	return gnarkProof, nil
}

// ConvertVerificationKey converts a SnarkJSVerificationKey into a Gnark-compatible VerifyingKey structure.
func ConvertVerificationKey(snarkVk *SnarkJSVerificationKey) (*groth16_bn254.VerifyingKey, error) {
	// Parse vk_alpha_1 (G1 point)
	alphaG1, err := stringToG1(snarkVk.VkAlpha1)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkAlpha1: %v", err)
	}
	// Parse vk_beta_2 (G2 point)
	betaG2, err := stringToG2(snarkVk.VkBeta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkBeta2: %v", err)
	}
	// Parse vk_gamma_2 (G2 point)
	gammaG2, err := stringToG2(snarkVk.VkGamma2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkGamma2: %v", err)
	}
	// Parse vk_delta_2 (G2 point)
	deltaG2, err := stringToG2(snarkVk.VkDelta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkDelta2: %v", err)
	}

	// Parse IC (G1 points for public inputs)
	numIC := len(snarkVk.IC)
	G1K := make([]bn254.G1Affine, numIC)
	for i, icPoint := range snarkVk.IC {
		icG1, err := stringToG1(icPoint)
		if err != nil {
			return nil, fmt.Errorf("failed to convert IC[%d]: %v", i, err)
		}
		G1K[i] = *icG1
	}

	// Construct the VerifyingKey
	vk := &groth16_bn254.VerifyingKey{}

	// Set G1 elements
	vk.G1.Alpha = *alphaG1
	vk.G1.K = G1K

	// Set G2 elements
	vk.G2.Beta = *betaG2
	vk.G2.Gamma = *gammaG2
	vk.G2.Delta = *deltaG2

	// Precompute the necessary values (e, gammaNeg, deltaNeg)
	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("failed to precompute verification key: %v", err)
	}

	return vk, nil
}

// VerifyProof verifies the Gnark proof using the provided verification key and public inputs.
func VerifyProof(gnarkProof *groth16_bn254.Proof, vk *groth16_bn254.VerifyingKey, publicInputs []bn254fr.Element) (bool, error) {
	// Verify the proof
	err := groth16_bn254.Verify(gnarkProof, vk, publicInputs)
	if err != nil {
		return false, fmt.Errorf("proof verification failed: %v", err)
	}

	// Convert the proof and verification key to recursion types (to check compatibility)
	_, err = recursion.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](gnarkProof)
	if err != nil {
		return false, fmt.Errorf("failed to convert proof to recursion proof: %v", err)
	}

	_, err = recursion.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	if err != nil {
		return false, fmt.Errorf("failed to convert verification key to recursion verification key: %v", err)
	}

	return true, nil
}
