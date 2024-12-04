package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/circom2gnark/parser"
)

func parseCircomProof(proofData, vkData, publicSignalsData []byte) (*parser.GnarkRecursionProof, *parser.GnarkRecursionPlaceholders) {
	// Unmarshal JSON data
	snarkProof, err := parser.UnmarshalCircomProofJSON(proofData)
	if err != nil {
		log.Fatalf("failed to unmarshal proof: %v", err)
	}

	snarkVk, err := parser.UnmarshalCircomVerificationKeyJSON(vkData)
	if err != nil {
		log.Fatalf("failed to unmarshal vkey: %v", err)
	}

	publicSignals, err := parser.UnmarshalCircomPublicSignalsJSON(publicSignalsData)
	if err != nil {
		log.Fatalf("failed to unmarshal public signals: %v", err)
	}

	// Verify the proof outside a recursive circuit
	gnarkProof, err := parser.ConvertCircomToGnark(snarkVk, snarkProof, publicSignals)
	if err != nil {
		log.Fatalf("failed to convert Circom proof to Gnark proof: %v", err)
	}

	verified, err := parser.VerifyProof(gnarkProof)
	if err != nil {
		log.Fatalf("failed to verify proof: %v", err)
	}
	if !verified {
		log.Fatalf("proof verification failed")
	}

	recursionPlaceholders, err := parser.PlaceholdersForRecursion(snarkVk, len(publicSignals), true)
	if err != nil {
		log.Fatalf("failed to create placeholders for recursion: %v", err)
	}

	recursionData, err := parser.ConvertCircomToGnarkRecursion(snarkVk, snarkProof, publicSignals, true)
	if err != nil {
		log.Fatalf("failed to convert Circom proof to Gnark recursion proof: %v", err)
	}
	return recursionData, recursionPlaceholders
}

func circom2gnarkRecursiveBls12377(proofData, vkData, publicSignalsData []byte, runtest bool) (groth16.Proof, groth16.VerifyingKey, witness.Witness, constraint.ConstraintSystem) {
	// Get the recursion proof and placeholders
	recursionData, recursionPlaceholders := parseCircomProof(proofData, vkData, publicSignalsData)

	// Create placeholder circuit
	placeholderCircuit := &VerifyCircomProofCircuit{
		recursionPlaceholders.Proof,
		recursionPlaceholders.Vk,
		recursionPlaceholders.Witness,
	}

	// Initialize variables for ccs, pk, vk
	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	// Check if we are running as a test
	if runtest {
		// Create the circuit assignment with actual values
		circuitAssignment := &VerifyCircomProofCircuit{
			Proof:        recursionData.Proof,
			PublicInputs: recursionData.PublicInputs,
		}

		if err := test.IsSolved(placeholderCircuit, circuitAssignment, ecc.BLS12_377.ScalarField()); err != nil {
			panic(err)
		}
		return nil, nil, nil, nil
	}

	// Check if the files exist
	ccs, pk, vk, err = LoadCircuit(ecc.BLS12_377, VerifyCircomProofCircuitType)
	if err != nil {
		if errors.Is(err, ErrCircuitDoesNotExist) {
			// Files do not exist, compile the circuit
			fmt.Println("Compiling circuit...")
			ccs, pk, vk, err = CompileCircuit(placeholderCircuit, ecc.BLS12_377.ScalarField(), VerifyCircomProofCircuitType)
			if err != nil {
				log.Fatalf("Failed to compile circuit: %v", err)
			}
		} else {
			log.Fatalf("Failed to load circuit: %v", err)
		}
	}

	// Create the circuit assignment with actual values
	circuitAssignment := &VerifyCircomProofCircuit{
		Proof:        recursionData.Proof,
		PublicInputs: recursionData.PublicInputs,
	}

	// Create the witness
	witnessFull, err := frontend.NewWitness(circuitAssignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	// Create the public witness
	publicWitness, err := witnessFull.Public()
	if err != nil {
		log.Fatalf("Failed to create public witness: %v", err)
	}

	// Create the proof
	fmt.Println("Generating a recursive proof BLS12-377 of an independent Circom proof...")
	startTime := time.Now()
	proof, err := groth16.Prove(ccs, pk, witnessFull, stdgroth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		log.Fatalf("Failed to create proof: %v", err)
	}
	fmt.Printf("Proving Recursion time: %v\n", time.Since(startTime))

	// Verify the proof
	fmt.Println("Verifying...")
	startTime = time.Now()
	err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		log.Fatalf("Failed to verify proof: %v", err)
	}
	fmt.Printf("Recursive proof verification succeeded! took %s\n", time.Since(startTime))
	return proof, vk, publicWitness, ccs

}
