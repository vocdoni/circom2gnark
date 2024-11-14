package main

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
)

// InnerCircuit is a minimal circuit that will be used to generate the initial proof.
type InnerCircuit struct {
	X, Y, Output frontend.Variable `gnark:",public"`
}

func (c *InnerCircuit) Define(api frontend.API) error {
	result := api.Mul(c.X, c.Y)
	api.AssertIsEqual(result, c.Output)
	return nil
}

// OuterCircuit is the recursive circuit that verifies the InnerCircuit proof.
type OuterCircuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	PublicInputs stdgroth16.Witness[sw_bn254.ScalarField]                                     `gnark:",public"`
}

func (c *OuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("failed to initialize verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.PublicInputs)
}

func TestRecursiveVerificationWithConstantVK(t *testing.T) {
	// Step 1: Set up the inner circuit and generate a proof
	t.Logf("Setting up inner circuit...")
	innerCircuit := &InnerCircuit{}
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, innerCircuit)
	if err != nil {
		t.Fatalf("failed to compile inner circuit: %v", err)
	}

	// Create proving and verifying keys for the inner circuit
	t.Logf("Setting up inner circuit...")
	innerPk, innerVk, err := groth16.Setup(innerCcs)
	if err != nil {
		t.Fatalf("failed to set up inner circuit keys: %v", err)
	}

	// Create a valid witness for the inner circuit
	innerWitness := &InnerCircuit{
		X:      3,
		Y:      5,
		Output: 15, // 3 * 5 = 15
	}
	innerFullWitness, err := frontend.NewWitness(innerWitness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("failed to create inner witness: %v", err)
	}

	// Generate the proof for the inner circuit
	t.Logf("Generating proof for inner circuit...")
	innerProof, err := groth16.Prove(innerCcs, innerPk, innerFullWitness)
	if err != nil {
		t.Fatalf("failed to generate inner proof: %v", err)
	}

	// Step 2: Convert VerifyingKey to circuit format and set it as a constant
	vvk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	if err != nil {
		t.Fatalf("failed to convert inner verifying key to circuit format: %v", err)
	}

	// Step 3: Set up the outer circuit and use the inner proof as input
	outerCircuit := &OuterCircuit{
		VerifyingKey: vvk,
		PublicInputs: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
	}

	// Convert proof and public inputs to the format expected by the outer circuit
	outerProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	if err != nil {
		t.Fatalf("failed to convert inner proof to recursive proof format: %v", err)
	}
	innerFullWitnessPublic, err := innerFullWitness.Public()
	if err != nil {
		t.Fatalf("failed to create public inner witness: %v", err)
	}
	outerPublicInputs, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerFullWitnessPublic)
	if err != nil {
		t.Fatalf("failed to convert inner witness public inputs: %v", err)
	}

	// Set up the circuit assignment
	outerAssignment := &OuterCircuit{
		Proof:        outerProof,
		PublicInputs: outerPublicInputs,
	}

	// Test the solve circuit
	t.Logf("Testing outer circuit...")
	if err = test.IsSolved(outerCircuit, outerAssignment, ecc.BLS12_377.ScalarField()); err != nil {
		t.Fatalf("failed to solve outer circuit: %v", err)
	}
}
