package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
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
// It has three dummy public inputs to simulate a real witness.
// The circuit asserts that the three inputs are equal.
type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[FR]
	DummyInput1  frontend.Variable `gnark:",public"`
	DummyInput2  frontend.Variable `gnark:",public"`
	DummyInput3  frontend.Variable `gnark:",public"`
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	api.AssertIsEqual(c.DummyInput1, c.DummyInput2)
	api.AssertIsEqual(c.DummyInput2, c.DummyInput3)
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

func TestRecursionToSolidity(t *testing.T) {
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
	outerProof, err := groth16.Prove(ccs, pk, secretWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		t.Fatalf("outer proving failed: %v", err)
	}

	// Convert the outer proof to Solidity.
	proofSolidity := parser.Groth16CommitmentProof{}
	if err := proofSolidity.FromGnarkProof(outerProof); err != nil {
		t.Fatalf("failed to convert outer proof to Solidity: %v", err)
	}

	t.Logf("--------------- Solidity proof JSON-----------------\n")
	jp, err := json.MarshalIndent(proofSolidity, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal proof to JSON: %v", err)
	}
	t.Logf("%s\n", jp)
	t.Logf("----------------------------------------------------\n")

	abiEncoded, err := proofSolidity.ABIEncode()
	if err != nil {
		t.Fatalf("failed to encode proof to ABI: %v", err)
	}
	t.Logf("Serialized proof: %x\n", abiEncoded)

	// Verify the outer proof.
	if err := groth16.Verify(outerProof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
		t.Logf("Outer recursive proof verification failed: %v", err)
	} else {
		t.Log("Outer recursive proof verification succeeded!")
	}

	// Cast vk to bn254 VerifyingKey and force precomputation (not sure if necessary).
	v := vk.(*groth16_bn254.VerifyingKey)
	if err := v.Precompute(); err != nil {
		t.Fatalf("failed to precompute verification key: %v", err)
	}

	// Export Solidity verifier.
	fd, err := os.Create("vkey.sol")
	if err != nil {
		t.Fatalf("failed to open vk.sol: %v", err)
	}
	buf := bytes.NewBuffer(nil)
	if err := vk.ExportSolidity(buf); err != nil {
		t.Fatalf("failed to export vk.sol: %v", err)
	}
	fd.Write(buf.Bytes())
	fd.Close()
	t.Logf("Solidity verifier written to vkey.sol\n")
}
