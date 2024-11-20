package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

const (
	numProofs = 100
)

// VerifyCircomProofCircuit is the circuit that verifies the Circom proof inside Gnark
type VerifyCircomProofCircuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	verifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	PublicInputs stdgroth16.Witness[sw_bn254.ScalarField]                                     `gnark:",public"`
}

func (c *VerifyCircomProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.verifyingKey, c.Proof, c.PublicInputs, stdgroth16.WithCompleteArithmetic())
}

// AggregateProofCircuit is the circuit that verifies multiple proofs inside Gnark
type AggregateProofCircuit struct {
	Proofs       [numProofs]BatchProofData
	verifyingKey stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
	PublicHash   frontend.Variable                                                                   `gnark:",public"`
}

type BatchProofData struct {
	Proof        stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	PublicInputs stdgroth16.Witness[sw_bls12377.ScalarField]
}

func (c *AggregateProofCircuit) Define(api frontend.API) error {
	// Initialize MiMC hash function
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Compute the hash of all public inputs
	for i := 0; i < numProofs; i++ {
		for _, input := range c.Proofs[i].PublicInputs.Public {
			// Write the limbs of each public input to the hash function
			hFunc.Write(input.Limbs...)
		}
	}
	computedHash := hFunc.Sum()
	// Assert that the computed hash matches the provided PublicHash
	api.AssertIsEqual(computedHash, c.PublicHash)
	api.Println("=> Computed inputs hash: ", computedHash)

	// Proceed with proof verification
	verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	for i := 0; i < numProofs; i++ {
		api.Println("=> Verifying in-circuit proof: ", i)
		if err := verifier.AssertProof(c.verifyingKey, c.Proofs[i].Proof, c.Proofs[i].PublicInputs); err != nil {
			return fmt.Errorf("assert proof: %w", err)
		}
	}
	return nil
}

// AggregateProofCircuitBN254 is the circuit that verifies the proof aggregation using BN254 curve
type AggregateProofCircuitBN254 struct {
	Proof        stdgroth16.Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine]
	verifyingKey stdgroth16.VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl] `gnark:"-"`
	PublicInputs stdgroth16.Witness[sw_bw6761.ScalarField]                                       `gnark:",public"`
}

func (c *AggregateProofCircuitBN254) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.verifyingKey, c.Proof, c.PublicInputs, stdgroth16.WithCompleteArithmetic())
}
