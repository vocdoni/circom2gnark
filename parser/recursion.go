package parser

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
	recursion "github.com/consensys/gnark/std/recursion/groth16"

	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// ConvertCircomToGnarkRecursion converts a Circom proof, verification key, and public signals to the Gnark recursion proof format.
// It returns in addition a set of placeholders needed to define the recursive circuit.
// If fixedVk is true, the verification key is fixed and must be defined as 'gnark:"-"' in the Circuit.
func ConvertCircomToGnarkRecursion(circomProof *CircomProof, circomVk *CircomVerificationKey, circomPublicSignals []string, fixedVk bool) (*GnarkRecursionProof, *GnarkRecursionPlaceholders, error) {
	// Convert public signals to field elements
	publicInputs, err := ConvertPublicInputs(circomPublicSignals)
	if err != nil {
		return nil, nil, err
	}

	// Convert the proof and verification key to gnark types
	gnarkProof, err := ConvertProof(circomProof)
	if err != nil {
		return nil, nil, err
	}

	// Convert the proof and verification key to recursion types
	recursionProof, err := recursion.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](gnarkProof)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert proof to recursion proof: %w", err)
	}

	// Convert the verification key to recursion verification key
	gnarkVk, err := ConvertVerificationKey(circomVk)
	if err != nil {
		return nil, nil, err
	}

	// Transform the public inputs to emulated elements for the recursion circuit
	publicInputElementsEmulated := make([]emulated.Element[sw_bn254.ScalarField], len(publicInputs))
	for i, input := range publicInputs {
		bigIntValue := input.BigInt(new(big.Int))
		elem := emulated.ValueOf[sw_bn254.ScalarField](bigIntValue)
		publicInputElementsEmulated[i] = elem
	}

	recursionPublicInputs := recursion.Witness[sw_bn254.ScalarField]{
		Public: publicInputElementsEmulated,
	}

	// Create placeholders
	var placeholders *GnarkRecursionPlaceholders
	if fixedVk {
		placeholders, err = createPlaceholdersForRecursionWithFixedVk(gnarkVk, len(publicInputs))
	} else {
		placeholders, err = createPlaceholdersForRecursion(gnarkVk, len(publicInputs))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create placeholders for recursion: %w", err)
	}

	// Create assignments
	assignments := &GnarkRecursionProof{
		Proof:        recursionProof,
		PublicInputs: recursionPublicInputs,
	}
	if !fixedVk {
		// Create the recursion types
		recursionVk, err := recursion.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
		}
		assignments.Vk = recursionVk
	}

	return assignments,
		placeholders,
		nil
}

// createPlaceholdersForRecursion creates placeholders for the recursion proof and verification key.
// It returns a set of placeholders needed to define the recursive circuit.
// Use this function when the verification key is fixed (defined as 'gnark:"-"').
func createPlaceholdersForRecursionWithFixedVk(gnarkVk *groth16_bn254.VerifyingKey, numberOfPublicInputs int) (*GnarkRecursionPlaceholders, error) {
	if gnarkVk == nil || numberOfPublicInputs < 0 {
		return nil, fmt.Errorf("invalid inputs to create placeholders for recursion")
	}
	placeholderVk, err := recursion.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
	}

	placeholderWitness := recursion.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], numberOfPublicInputs),
	}
	placeholderProof := recursion.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{}

	return &GnarkRecursionPlaceholders{
		Vk:      placeholderVk,
		Witness: placeholderWitness,
		Proof:   placeholderProof,
	}, nil
}

// createPlaceholdersForRecursion creates placeholders for the recursion proof and verification key.
// It returns a set of placeholders needed to define the recursive circuit.
// Use this function when the verification key is not fixed.
func createPlaceholdersForRecursion(gnarkVk *groth16_bn254.VerifyingKey, numberOfPublicInputs int) (*GnarkRecursionPlaceholders, error) {
	placeholders, err := createPlaceholdersForRecursionWithFixedVk(gnarkVk, numberOfPublicInputs)
	if err != nil {
		return nil, err
	}
	placeholders.Vk.G1.K = make([]sw_bn254.G1Affine, len(placeholders.Vk.G1.K))
	return placeholders, nil
}
