package test

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/circom2gnark/parser"
)

func TestRecursionToCircom_Debug(t *testing.T) {
	// Compute the inner Groth16 proof (proving 3*5==15).
	innerCcs, innerVK, innerPubWitness, innerProof := computeInnerProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())

	// Convert inner components to recursion types.
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	if err != nil {
		t.Fatalf("failed to convert inner VK: %v", err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPubWitness)
	if err != nil {
		t.Fatalf("failed to convert inner witness: %v", err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	if err != nil {
		t.Fatalf("failed to convert inner proof: %v", err)
	}

	// Build the outer assignment with the recursion types.
	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
		DummyInput1:  1,
		DummyInput2:  1,
		DummyInput3:  1,
	}

	// Create a placeholder outer circuit (to deduce public input sizes).
	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}

	// Compile the outer circuit.
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	if err != nil {
		t.Fatalf("failed to compile outer circuit: %v", err)
	}
	t.Logf("Outer circuit compiled with %d constraints", ccs.GetNbConstraints())

	// Groth16 setup for the outer circuit.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("outer circuit setup failed: %v", err)
	}

	// Create the prover witness from the outer assignment.
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("failed to create secret witness: %v", err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		t.Fatalf("failed to get public witness: %v", err)
	}

	// Prove the outer (recursive) circuit.
	outerProof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		t.Fatalf("outer proving failed: %v", err)
	}

	// Verify the outer proof.
	if err := groth16.Verify(outerProof, vk, publicWitness); err != nil {
		t.Fatalf("outer proof verification failed: %v", err)
	}
	t.Log("Outer recursive proof verification succeeded!")

	// Cast vk to bn254 VerifyingKey and force precomputation (not sure if necessary).
	v := vk.(*groth16_bn254.VerifyingKey)
	if err := v.Precompute(); err != nil {
		t.Fatalf("failed to precompute verification key: %v", err)
	}

	// Log lengths of public input witness and IC array.
	vec, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		t.Fatalf("expected public witness vector to be of type bn254fr.Vector, got %T", publicWitness.Vector())
	}
	t.Logf("Public witness length (from witness vector): %d", len(vec))
	t.Logf("Length of vk.G1.K (IC array): %d", len(v.G1.K))

	// Convert the outer proof into Circom‑compatible objects.
	circomProof, circomVk, circomPub, err := parser.ConvertGnarkToCircom(outerProof, v, publicWitness)
	if err != nil {
		t.Fatalf("conversion to Circom format failed: %v", err)
	}

	// Marshal Circom objects to JSON.
	proofJSON, err := parser.MarshalCircomProofJSON(circomProof)
	if err != nil {
		t.Fatalf("failed to marshal proof JSON: %v", err)
	}
	vkJSON, err := parser.MarshalCircomVerificationKeyJSON(circomVk)
	if err != nil {
		t.Fatalf("failed to marshal vk JSON: %v", err)
	}
	pubJSON, err := parser.MarshalCircomPublicSignalsJSON(circomPub)
	if err != nil {
		t.Fatalf("failed to marshal public signals JSON: %v", err)
	}

	// Write JSON files and exported Solidity verifier to a temporary directory.
	tempDir, err := os.MkdirTemp("", "circom2gnark_recursion_test")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}

	// Write JSON files to the temporary directory.
	t.Logf("Writing debug Circom JSON files to %s", tempDir)
	if err := os.WriteFile(tempDir+"/proof.json", proofJSON, 0644); err != nil {
		t.Fatalf("failed to write proof.json: %v", err)
	}
	if err := os.WriteFile(tempDir+"/vkey.json", vkJSON, 0644); err != nil {
		t.Fatalf("failed to write vkey.json: %v", err)
	}
	if err := os.WriteFile(tempDir+"/public_signals.json", pubJSON, 0644); err != nil {
		t.Fatalf("failed to write public_signals.json: %v", err)
	}

	t.Logf("Test files written to %s", tempDir)
	t.Logf("To verify with snarkjs run:\n  snarkjs groth16 verify %s/vkey.json %s/public_signals.json %s/proof.json",
		tempDir, tempDir, tempDir)

	// Verify the Circom proof using go-snark (a Go implementation of Circom proof system).
	ok, err = parser.VerifyCircomProof(tempDir+"/proof.json", tempDir+"/vkey.json", tempDir+"/public_signals.json")
	if err != nil {
		t.Fatalf("failed to verify Circom proof: %v", err)
	}
	if !ok {
		t.Fatal("Circom proof verification failed")
	}
}
