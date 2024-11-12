package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
)

// aggregateProofToBn254 transforms the aggregate proof to a recursion proof using BN254 curve
func aggregateProofToBn254(proof *innerProof, vkInner groth16.VerifyingKey, ccsInner constraint.ConstraintSystem) error {
	placeHolderCircuit, err := createAggregationBn254PlaceholderData(ccsInner)
	if err != nil {
		return fmt.Errorf("failed to create placeholder data: %w", err)
	}

	circuitAssignments, err := createAggregationBn254CircuitData(proof, vkInner)
	if err != nil {
		return fmt.Errorf("failed to create circuit data: %w", err)
	}

	// Test the solve circuit
	if err = test.IsSolved(placeHolderCircuit, circuitAssignments, ecc.BN254.ScalarField()); err != nil {
		log.Fatalf("Failed to test solve circuit: %v", err)
	}

	// Check if the circuit files exist, else compile the circuit and write the files
	ccs, pk, vk, err := LoadCircuit(ecc.BN254, AggregateProofCircuitBN254Type)
	if err != nil {
		if errors.Is(err, ErrCircuitDoesNotExist) {
			// Files do not exist, compile the circuit
			fmt.Println("Compiling bn254 aggregate circuit...")
			// Create placeholder proofs
			// Compile the circuit
			ccs, pk, vk, err = CompileCircuit(placeHolderCircuit, ecc.BN254.ScalarField(), AggregateProofCircuitBN254Type)
			if err != nil {
				log.Fatalf("Failed to compile circuit: %v", err)
			}
		} else {
			log.Fatalf("Failed to load circuit: %v", err)
		}
	}

	fmt.Println("Creating witness for final bn254 aggregation proof...")
	witnessFull, err := frontend.NewWitness(circuitAssignments, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	fmt.Println("Creating final bn254 aggregation proof")
	startTime := time.Now()
	proof2, err := groth16.Prove(ccs, pk, witnessFull)
	if err != nil {
		return fmt.Errorf("failed to create proof: %w", err)
	}
	fmt.Printf("Proving Recursion time: %v\n", time.Since(startTime))

	// Verify the proof
	publicWitness, err := witnessFull.Public()
	if err != nil {
		log.Fatalf("Failed to create public witness: %v", err)
	}
	fmt.Println("Verifying...")
	startTime = time.Now()
	err = groth16.Verify(proof2, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("failed to verify proof: %w", err)
	}
	fmt.Printf("Recursive proof verification succeeded! took %s\n", time.Since(startTime))

	return nil
}

func createAggregationBn254PlaceholderData(ccs constraint.ConstraintSystem) (*AggregateProofCircuitBN254, error) {
	return &AggregateProofCircuitBN254{
		Proof:        stdgroth16.PlaceholderProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](ccs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](ccs),
		PublicInputs: stdgroth16.PlaceholderWitness[sw_bw6761.ScalarField](ccs),
	}, nil
}

func createAggregationBn254CircuitData(proof *innerProof, vk groth16.VerifyingKey) (*AggregateProofCircuitBN254, error) {
	// Create the proofs for the aggregate recursion circuit
	aggregateProofCircuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl](vk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
	}
	p, err := stdgroth16.ValueOfProof[sw_bw6761.G1Affine, sw_bw6761.G2Affine](proof.p)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proof to recursion proof: %w", err)
	}
	w, err := stdgroth16.ValueOfWitness[sw_bw6761.ScalarField](proof.w)
	if err != nil {
		return nil, fmt.Errorf("failed to convert witness to recursion witness: %w", err)
	}

	return &AggregateProofCircuitBN254{
		VerifyingKey: aggregateProofCircuitVk,
		Proof:        p,
		PublicInputs: w,
	}, nil
}
