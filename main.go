package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"

	"github.com/vocdoni/circomgnark/parser"
)

func init() {
	logger.Logger().Level(zerolog.DebugLevel)
}

func main() {
	// Load proof.json
	proofData, err := os.ReadFile("proof.json")
	if err != nil {
		fmt.Printf("Error reading proof.json: %v\n", err)
		return
	}

	// Load vkey.json
	vkData, err := os.ReadFile("vkey.json")
	if err != nil {
		fmt.Printf("Error reading vkey.json: %v\n", err)
		return
	}

	// Load public signals
	publicSignalsData, err := os.ReadFile("public_signals.json")
	if err != nil {
		fmt.Printf("Error reading public signals: %v\n", err)
		return
	}

	// Parse proof
	snarkProof, err := parser.ParseSnarkJSProof(proofData)
	if err != nil {
		fmt.Printf("Error parsing proof: %v\n", err)
		return
	}

	// Parse verification key
	snarkVk, err := parser.ParseSnarkJSVerificationKey(vkData)
	if err != nil {
		fmt.Printf("Error parsing verification key: %v\n", err)
		return
	}

	// Parse public signals
	var publicSignals []string
	err = json.Unmarshal(publicSignalsData, &publicSignals)
	if err != nil {
		fmt.Printf("Error parsing public signals: %v\n", err)
		return
	}
	publicInputs, err := parser.ParsePublicInputs(publicSignals)
	if err != nil {
		fmt.Printf("Error converting public inputs: %v\n", err)
		return
	}

	for i, elem := range publicInputs {
		fmt.Printf("Public input %d: %v\n", i, elem)
	}

	// Convert proof to Gnark format
	fmt.Println("Converting proof...")
	gnarkProof, err := parser.ConvertProof(snarkProof)
	if err != nil {
		fmt.Printf("Error converting proof: %v\n", err)
		return
	}

	// Convert verification key to Gnark format
	gnarkVk, err := parser.ConvertVerificationKey(snarkVk)
	if err != nil {
		fmt.Printf("Error converting verification key: %v\n", err)
		return
	}

	fmt.Printf("Verifying proof outside the recursive circuit with %d public inputs...\n", len(publicInputs))
	// Verify the proof outside the circuit
	valid, err := parser.VerifyProof(gnarkProof, gnarkVk, publicInputs)
	if err != nil {
		fmt.Printf("Proof verification failed: %v\n", err)
		return
	}
	if valid {
		fmt.Println("Proof is valid!")
	} else {
		fmt.Println("Proof is invalid!")
		return
	}

	fmt.Printf("Transforming proof and verification key to recursion types...\n")
	// Convert the proof and verification key to recursion types
	recursionProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](gnarkProof)
	if err != nil {
		fmt.Printf("Failed to convert proof to recursion proof: %v\n", err)
		return
	}

	recursionVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
	if err != nil {
		fmt.Printf("Failed to convert verification key to recursion verification key: %v\n", err)
		return
	}

	// Transform the public inputs to emulated elements for the recursion circuit
	publicInputElementsEmulated := make([]emulated.Element[sw_bn254.ScalarField], len(publicInputs))
	for i, input := range publicInputs {
		bigIntValue := input.BigInt(new(big.Int))
		elem := emulated.ValueOf[sw_bn254.ScalarField](bigIntValue)
		publicInputElementsEmulated[i] = elem
	}

	for i, elem := range publicInputElementsEmulated {
		fmt.Printf("Public input emulated %d: %v\n", i, elem)
	}

	recursionPublicInputs := stdgroth16.Witness[sw_bn254.ScalarField]{
		Public: publicInputElementsEmulated,
	}

	// Step 1: Determine the number of public inputs
	numPublicInputs := len(gnarkVk.G1.K) - 1 // Subtract 1 for the one wire

	// Step 2: Create placeholder verifying key
	placeholderVk := stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		G1: struct{ K []sw_bn254.G1Affine }{
			K: make([]sw_bn254.G1Affine, len(gnarkVk.G1.K)),
		},
		G2: struct {
			GammaNeg, DeltaNeg sw_bn254.G2Affine
		}{},
		E:                            sw_bn254.GTEl{},
		CommitmentKeys:               nil,
		PublicAndCommitmentCommitted: nil,
	}

	// Step 3: Create placeholder witness
	placeholderWitness := stdgroth16.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], numPublicInputs),
	}

	// Step 4: Create placeholder circuit
	placeholderCircuit := &VerifyCircomProofCircuit{
		Proof:        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{},
		VerifyingKey: placeholderVk,
		PublicInputs: placeholderWitness,
	}

	fmt.Printf("Placeholder VK G1.K length: %d\n", len(placeholderVk.G1.K))
	fmt.Printf("Actual VK G1.K length: %d\n", len(recursionVk.G1.K))

	fmt.Printf("Placeholder Witness Public length: %d\n", len(placeholderWitness.Public))
	fmt.Printf("Actual Witness Public length: %d\n", len(recursionPublicInputs.Public))

	// Compile the circuit
	startTime := time.Now()
	fmt.Println("Compiling circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, placeholderCircuit)
	if err != nil {
		fmt.Printf("Compile failed: %v\n", err)
		return
	}
	fmt.Printf("Compilation time: %v\n", time.Since(startTime))

	// Create the circuit assignment with actual values
	circuitAssignment := &VerifyCircomProofCircuit{
		Proof:        recursionProof,
		VerifyingKey: recursionVk,
		PublicInputs: recursionPublicInputs,
	}

	// Create the witness
	startTime = time.Now()
	fmt.Println("Creating witness...")
	witnessFull, err := frontend.NewWitness(circuitAssignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Failed to create witness: %v\n", err)
		return
	}

	// Create the public witness
	publicWitness, err := witnessFull.Public()
	if err != nil {
		fmt.Printf("Failed to create public witness: %v\n", err)
		return
	}
	fmt.Printf("Witness creation time: %v\n", time.Since(startTime))

	// Generate the proving and verifying keys
	startTime = time.Now()
	fmt.Println("Setting up proving and verifying keys...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("Setup failed: %v\n", err)
		return
	}
	fmt.Printf("Setup time: %v\n", time.Since(startTime))

	// Write the proving key to a file
	vkfile, err := os.Create("pk.bin")
	if err != nil {
		fmt.Printf("Error creating pk.bin: %v\n", err)
		return
	}
	defer vkfile.Close()
	_, err = pk.WriteTo(vkfile)
	if err != nil {
		fmt.Printf("Error writing proving key to pk.bin: %v\n", err)
		return
	}
	fmt.Println("Wrote proving key to pk.bin")

	// Write verifying key to a file
	vkfile, err = os.Create("vk.bin")
	if err != nil {
		fmt.Printf("Error creating vk.bin: %v\n", err)
		return
	}
	defer vkfile.Close()
	_, err = vk.WriteTo(vkfile)
	if err != nil {
		fmt.Printf("Error writing verifying key to vk.bin: %v\n", err)
		return
	}
	fmt.Println("Wrote verifying key to vk.bin")

	// Write circuit to a file
	circuitfile, err := os.Create("circuit.r1cs")
	if err != nil {
		fmt.Printf("Error creating circuit.r1cs: %v\n", err)
		return
	}
	defer circuitfile.Close()
	_, err = ccs.WriteTo(circuitfile)
	if err != nil {
		fmt.Printf("Error writing circuit to circuit.r1cs: %v\n", err)
		return
	}
	fmt.Println("Wrote circuit to circuit.r1cs")

	// Create the proof
	fmt.Println("Proving...")
	startTime = time.Now()
	proof, err := groth16.Prove(ccs, pk, witnessFull)
	if err != nil {
		fmt.Printf("Proving failed: %v\n", err)
		return
	}
	fmt.Printf("Proving Recursion time: %v\n", time.Since(startTime))

	// Verify the proof
	fmt.Println("Verifying...")
	startTime = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}
	fmt.Printf("Recursive proof verification succeeded! took %s\n", time.Since(startTime))
}

// VerifyCircomProofCircuit is the circuit that verifies the Circom proof inside Gnark
type VerifyCircomProofCircuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	PublicInputs stdgroth16.Witness[sw_bn254.ScalarField]
}

func (c *VerifyCircomProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.PublicInputs)
}
