package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

const (
	numProofs = 1
)

// VerifyCircomProofCircuit is the circuit that verifies the Circom proof inside Gnark
type VerifyCircomProofCircuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	PublicInputs stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`
}

func (c *VerifyCircomProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.PublicInputs, stdgroth16.WithCompleteArithmetic())
}

// AggregateProofCircuit is the circuit that verifies multiple proofs inside Gnark
type AggregateProofCircuit struct {
	Proofs       [numProofs]BatchProofData
	VerifyingKey stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
}

// BatchProofData is the data structure that holds the proof and public inputs for each proof
type BatchProofData struct {
	Proof        stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	PublicInputs stdgroth16.Witness[sw_bls12377.ScalarField] `gnark:",public"`
}

func (c *AggregateProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	for i := 0; i < numProofs; i++ {
		fmt.Printf("Verifying proof %d\n", i)
		if err := verifier.AssertProof(c.VerifyingKey, c.Proofs[i].Proof, c.Proofs[i].PublicInputs); err != nil {
			return fmt.Errorf("assert proof: %w", err)
		}
		fmt.Printf("Proof %d verified\n", i)
	}
	return nil
}

// AggregateProofCircuitBN254 is the circuit that verifies the proof aggregation using BN254 curve
type AggregateProofCircuitBN254 struct {
	Proof        stdgroth16.Proof[sw_bw6761.G1Affine, sw_bw6761.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]
	PublicInputs stdgroth16.Witness[sw_bw6761.ScalarField] `gnark:",public"`
}

func (c *AggregateProofCircuitBN254) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.PublicInputs, stdgroth16.WithCompleteArithmetic())
}
