package test

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/circom2gnark/parser"
)

// --- Debug Helper Functions ---

func printG1(label string, p *bn254.G1Affine) {
	x := p.X.BigInt(new(big.Int))
	y := p.Y.BigInt(new(big.Int))
	fmt.Printf("%s:\n  X = %s\n  Y = %s\n", label, x.String(), y.String())
}

func printG2(label string, p *bn254.G2Affine) {
	x0 := p.X.A0.BigInt(new(big.Int))
	x1 := p.X.A1.BigInt(new(big.Int))
	y0 := p.Y.A0.BigInt(new(big.Int))
	y1 := p.Y.A1.BigInt(new(big.Int))
	fmt.Printf("%s:\n  X.A0 = %s\n  X.A1 = %s\n  Y.A0 = %s\n  Y.A1 = %s\n",
		label, x0.String(), x1.String(), y0.String(), y1.String())
}

// --- Inner and Outer Circuit Definitions ---

// InnerCircuitNative proves P*Q == N with N public.
type InnerCircuitNative struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	api.AssertIsDifferent(c.P, 1)
	api.AssertIsDifferent(c.Q, 1)
	return nil
}

// computeInnerProof compiles, sets up, assigns, proves, and verifies the inner circuit.
func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitNative{})
	if err != nil {
		panic(fmt.Sprintf("inner circuit compilation failed: %v", err))
	}
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		panic(fmt.Sprintf("inner circuit setup failed: %v", err))
	}

	innerAssignment := &InnerCircuitNative{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(fmt.Sprintf("creating inner witness failed: %v", err))
	}
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(fmt.Sprintf("inner proving failed: %v", err))
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(fmt.Sprintf("getting inner public witness failed: %v", err))
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness, stdgroth16.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(fmt.Sprintf("inner proof verification failed: %v", err))
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}

// OuterCircuit verifies an inner Groth16 proof using recursion.
type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

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

	// DEBUG: Print raw verifying key fields.
	fmt.Println("----- Verifying Key Debug Info -----")
	printG1("vk.G1.Alpha", &v.G1.Alpha)
	printG2("vk.G2.Beta", &v.G2.Beta)
	printG2("vk.G2.Gamma", &v.G2.Gamma)
	printG2("vk.G2.Delta", &v.G2.Delta)
	for i, pt := range v.G1.K {
		printG1(fmt.Sprintf("vk.G1.K[%d]", i), &pt)
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
	tempDir, err := os.MkdirTemp("", "circom_json_recursion_debug")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}

	// Export Solidity verifier.
	fd, err := os.OpenFile(tempDir+"/vk.sol", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open vk.sol: %v", err)
	}
	buf := bytes.NewBuffer(nil)
	if err := v.ExportSolidity(buf); err != nil {
		t.Fatalf("failed to export vk.sol: %v", err)
	}
	fd.Write(buf.Bytes())
	fd.Close()

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
