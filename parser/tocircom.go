package parser

import (
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
)

// ConvertGnarkToCircom converts a Gnark proof (its proof, verifying key, and public inputs)
// into Circom‑compatible objects. It returns a CircomProof, a CircomVerificationKey and the
// public signals as a slice of strings.
func ConvertGnarkToCircom(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) (*CircomProof, *CircomVerificationKey, []string, error) {
	// Extract the underlying vector from the public witness.
	vec, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected public witness vector to be of type bn254fr.Vector, got %T", publicWitness.Vector())
	}

	// Create a new GnarkProof with the proof, verifying key, and public inputs from Gnark.
	gnarkProof := &GnarkProof{
		Proof:        proof.(*groth16_bn254.Proof),
		VerifyingKey: vk.(*groth16_bn254.VerifyingKey),
		PublicInputs: vec,
	}

	// Convert the proof.
	piA, err := g1ToCircomString(&gnarkProof.Proof.Ar)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert proof.Ar: %w", err)
	}
	piC, err := g1ToCircomString(&gnarkProof.Proof.Krs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert proof.Krs: %w", err)
	}
	piB, err := g2ToCircomString(&gnarkProof.Proof.Bs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert proof.Bs: %w", err)
	}

	circomProof := &CircomProof{
		PiA:      piA,
		PiB:      piB,
		PiC:      piC,
		Protocol: "groth16",
	}
	// Convert the verification key.
	vkey := gnarkProof.VerifyingKey
	if vk == nil {
		return nil, nil, nil, fmt.Errorf("VerifyingKey is nil in gnarkProof")
	}

	vkAlpha1, err := g1ToCircomString(&vkey.G1.Alpha)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert vk.G1.Alpha: %w", err)
	}
	vkBeta2, err := g2ToCircomString(&vkey.G2.Beta)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert vk.G2.Beta: %w", err)
	}
	vkGamma2, err := g2ToCircomString(&vkey.G2.Gamma)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert vk.G2.Gamma: %w", err)
	}
	vkDelta2, err := g2ToCircomString(&vkey.G2.Delta)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert vk.G2.Delta: %w", err)
	}

	// Convert the IC array (G1 points for public inputs).
	ic := make([][]string, len(vkey.G1.K))
	for i, pt := range vkey.G1.K {
		ptStr, err := g1ToCircomString(&pt)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to convert IC[%d]: %w", i, err)
		}
		ic[i] = ptStr
	}

	// nPublic is expected to be the number of public inputs (IC should have length nPublic+1).
	nPublic := len(gnarkProof.PublicInputs)
	// For non-recursive proofs, nPublic = len(publicInputs). But in recursive proofs we may have
	// an extra element in IC. So if there are no public inputs and IC has more than one element,
	// trim IC to length 1.
	if nPublic == 0 && len(ic) > 1 {
		ic = ic[:1]
	}

	// Compute vk_alphabeta_12 = e(vk_alpha_1, vk_beta_2) in the Circom format.
	alphabeta, err := ComputeAlphabeta12(vkey.G1.Alpha, vkey.G2.Beta)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute vk_alphabeta_12: %w", err)
	}

	circomVk := &CircomVerificationKey{
		Protocol:      "groth16",
		Curve:         "bn128", // Circom uses "bn128" for bn254.
		NPublic:       nPublic,
		VkAlpha1:      vkAlpha1,
		VkBeta2:       vkBeta2,
		VkGamma2:      vkGamma2,
		VkDelta2:      vkDelta2,
		IC:            ic,
		VkAlphabeta12: alphabeta,
	}

	// Convert public inputs from bn254fr.Element to decimal strings.
	publicSignals := make([]string, len(gnarkProof.PublicInputs))
	for i, input := range gnarkProof.PublicInputs {
		publicSignals[i] = elementToString(input)
	}

	return circomProof, circomVk, publicSignals, nil
}

// g1ToCircomString converts a bn254 G1Affine point to a Circom‑compatible slice of strings.
// The returned slice is [ X, Y, "1" ] (all in decimal string format).
func g1ToCircomString(p *curve.G1Affine) ([]string, error) {
	if p == nil {
		return nil, fmt.Errorf("nil G1 point")
	}
	xBig := p.X.BigInt(new(big.Int))
	yBig := p.Y.BigInt(new(big.Int))
	return []string{
		xBig.String(),
		yBig.String(),
		"1",
	}, nil
}

// g2ToCircomString converts a bn254 G2Affine point to a Circom‑compatible 2D slice of strings.
// The returned value is of the form:
//
//	[ [ X.A0, X.A1 ], [ Y.A0, Y.A1 ], [ "1", "0" ] ]
//
// with all numbers in decimal.
func g2ToCircomString(p *curve.G2Affine) ([][]string, error) {
	if p == nil {
		return nil, fmt.Errorf("nil G2 point")
	}
	x0 := p.X.A0.BigInt(new(big.Int))
	x1 := p.X.A1.BigInt(new(big.Int))
	y0 := p.Y.A0.BigInt(new(big.Int))
	y1 := p.Y.A1.BigInt(new(big.Int))

	return [][]string{
		{x0.String(), x1.String()},
		{y0.String(), y1.String()},
		{"1", "0"},
	}, nil
}

// elementToString converts a bn254fr.Element to its decimal string representation.
func elementToString(e fr.Element) string {
	return e.BigInt(new(big.Int)).String()
}

// computeAlphabeta12 computes vk_alphabeta_12 = e(vk_alpha_1, vk_beta_2)
// and returns a 2×3×2 slice of decimal strings.
// The output format is:
//
//	[
//	  [ [C0.B0.A0, C0.B0.A1], [C0.B1.A0, C0.B1.A1], [C0.B2.A0, C0.B2.A1] ],
//	  [ [C1.B0.A0, C1.B0.A1], [C1.B1.A0, C1.B1.A1], [C1.B2.A0, C1.B2.A1] ]
//	]
func ComputeAlphabeta12(alpha curve.G1Affine, beta curve.G2Affine) ([][][]string, error) {
	// Compute the pairing; Pair expects slices.
	gt, err := curve.Pair([]curve.G1Affine{alpha}, []curve.G2Affine{beta})
	if err != nil {
		return nil, fmt.Errorf("failed to compute pairing: %v", err)
	}

	// We assume GT is of type bn254.GT (alias for fptower.E12) with structure:
	//   gt.C0 and gt.C1 are of type E6, each with fields B0, B1, B2 of type E2,
	//   and each E2 has fields A0, A1 of type fp.Element.
	out := make([][][]string, 2)
	for i := 0; i < 2; i++ {
		out[i] = make([][]string, 3)
		for j := 0; j < 3; j++ {
			out[i][j] = make([]string, 2)
		}
	}

	// Decompose GT
	c0 := gt.C0 // type E6
	c1 := gt.C1 // type E6

	// For C0
	out[0][0][0] = c0.B0.A0.BigInt(new(big.Int)).String()
	out[0][0][1] = c0.B0.A1.BigInt(new(big.Int)).String()
	out[0][1][0] = c0.B1.A0.BigInt(new(big.Int)).String()
	out[0][1][1] = c0.B1.A1.BigInt(new(big.Int)).String()
	out[0][2][0] = c0.B2.A0.BigInt(new(big.Int)).String()
	out[0][2][1] = c0.B2.A1.BigInt(new(big.Int)).String()

	// For C1
	out[1][0][0] = c1.B0.A0.BigInt(new(big.Int)).String()
	out[1][0][1] = c1.B0.A1.BigInt(new(big.Int)).String()
	out[1][1][0] = c1.B1.A0.BigInt(new(big.Int)).String()
	out[1][1][1] = c1.B1.A1.BigInt(new(big.Int)).String()
	out[1][2][0] = c1.B2.A0.BigInt(new(big.Int)).String()
	out[1][2][1] = c1.B2.A1.BigInt(new(big.Int)).String()

	return out, nil
}

// PublicWitnessFromVector creates a witness.Witness from a []fr.Element.
// It assumes that the entire vector represents the public inputs (with no secret inputs).
func PublicWitnessFromVector(vec []fr.Element) (witness.Witness, error) {
	// Use the field modulus from fr.Modulus().
	w, err := witness.New(fr.Modulus())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %v", err)
	}

	nbPublic := len(vec)
	nbSecret := 0

	// Create a buffered channel with capacity equal to the number of public elements.
	ch := make(chan any, nbPublic)
	for _, e := range vec {
		ch <- e
	}
	close(ch)

	// Fill the witness with the public values.
	if err := w.Fill(nbPublic, nbSecret, ch); err != nil {
		return nil, fmt.Errorf("failed to fill witness: %v", err)
	}
	return w, nil
}
