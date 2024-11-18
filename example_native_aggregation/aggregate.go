package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

type innerProof struct {
	p groth16.Proof
	w witness.Witness
}

/*func createAggregationPlaceholderData(vk groth16.VerifyingKey) (*AggregateProofCircuit, error) {
	placeholderVk, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
	}
	placeholderVk.G1.K = make([]sw_bls12377.G1Affine, len(placeholderVk.G1.K))

	placeHolderProofs := [numProofs]BatchProofData{}
	for i := 0; i < numProofs; i++ {
		numberOfPublicInputs := vk.NbPublicWitness()
		log.Printf("Number of public inputs: %d\n", numberOfPublicInputs)
		// Create placeholder witness
		placeholderWitness := stdgroth16.Witness[sw_bls12377.ScalarField]{
			Public: make([]emulated.Element[sw_bls12377.ScalarField], numberOfPublicInputs),
		}

		// Create placeholder proof

		//placeholderProof := stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
		//stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]()

		placeholderProof := stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{
			Commitments: make([]pedersen.Commitment[sw_bls12377.G1Affine], len(placeholderVk.CommitmentKeys)),
		}

		placeHolderProofs[i] = BatchProofData{
			Proof:        placeholderProof,
			PublicInputs: placeholderWitness,
		}
	}

	log.Printf("Number of G1.K %d\n", len(placeholderVk.G1.K))

	return &AggregateProofCircuit{
		Proofs:       placeHolderProofs,
		VerifyingKey: placeholderVk,
	}, nil
}
*/

func createAggregationPlaceholderData(ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) (*AggregateProofCircuit, error) {
	placeHolderProofs := [numProofs]BatchProofData{}
	for i := 0; i < numProofs; i++ {
		// Create placeholder proof
		placeHolderProofs[i] = BatchProofData{
			PublicInputs: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](ccs),
			Proof:        stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccs),
		}
	}
	vvk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
	}
	return &AggregateProofCircuit{
		Proofs:       placeHolderProofs,
		verifyingKey: vvk,
	}, nil
}

func createAggregationCircuitData(proofs []*innerProof) (*AggregateProofCircuit, error) {
	// Create the proofs for the aggregate recursion circuit
	aggregateCircuitData := &AggregateProofCircuit{}
	var err error
	for i := 0; i < numProofs; i++ {
		proofData := BatchProofData{}
		if proofData.PublicInputs, err = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](proofs[i].w); err != nil {
			return nil, fmt.Errorf("failed to convert witness to recursion witness: %w", err)
		}

		if proofData.Proof, err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proofs[i].p); err != nil {
			return nil, fmt.Errorf("failed to convert proof to recursion proof: %w", err)
		}
		aggregateCircuitData.Proofs[i] = proofData
	}
	return aggregateCircuitData, nil
}

func AggregateProofs(proofs []*innerProof, vkProofs groth16.VerifyingKey, ccsInner constraint.ConstraintSystem) (
	*innerProof, groth16.VerifyingKey,
	constraint.ConstraintSystem, error) {
	if len(proofs) != numProofs {
		log.Fatalf("Number of proofs should be %d", numProofs)
	}

	placeHolderCircuit, err := createAggregationPlaceholderData(ccsInner, vkProofs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create placeholder data: %w", err)
	}

	circuitAssignments, err := createAggregationCircuitData(proofs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create circuit data: %w", err)
	}

	// Test the solve circuit
	if err = test.IsSolved(placeHolderCircuit, circuitAssignments, ecc.BW6_761.ScalarField()); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to solve circuit: %w", err)
	}

	// Check if the circuit files exist, else compile the circuit and write the files
	ccs, pk, vk, err := LoadCircuit(ecc.BW6_761, AggregateProofCircuitType)
	if err != nil {
		if errors.Is(err, ErrCircuitDoesNotExist) {
			// Files do not exist, compile the circuit
			fmt.Println("Compiling aggregate circuit...")
			// Create placeholder proofs
			// Compile the circuit
			ccs, pk, vk, err = CompileCircuit(placeHolderCircuit, ecc.BW6_761.ScalarField(), AggregateProofCircuitType)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to compile circuit: %w", err)
			}
		} else {
			return nil, nil, nil, fmt.Errorf("failed to load circuit: %w", err)
		}
	}

	fmt.Println("Creating witness for final aggregation proof...")
	witnessFull, err := frontend.NewWitness(circuitAssignments, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create witness: %w", err)
	}

	fmt.Println("Creating final aggregation proof")
	startTime := time.Now()
	proof2, err := groth16.Prove(ccs, pk, witnessFull, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create proof: %w", err)
	}
	fmt.Printf("Proving Recursion time: %v\n", time.Since(startTime))

	// Verify the proof
	publicWitness, err := witnessFull.Public()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create public witness: %w", err)
	}
	fmt.Println("Verifying...")
	startTime = time.Now()
	err = groth16.Verify(proof2, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify proof: %w", err)
	}
	fmt.Printf("Recursive proof verification succeeded! took %s\n", time.Since(startTime))

	return &innerProof{p: proof2, w: publicWitness}, vk, ccs, nil
}
