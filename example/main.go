package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/circom2gnark/parser"
)

func main() {
	runtest := false
	circomDataDir := "circom_data"
	flag.BoolVar(&runtest, "test", false, "Run as test")
	flag.StringVar(&circomDataDir, "circom-data", "circom_data", "Directory containing the Circom JSON data files")
	flag.Parse()

	// Load proof.json
	proofData, err := os.ReadFile(fmt.Sprintf("%s/proof.json", circomDataDir))
	if err != nil {
		log.Fatalf("failed to read proof: %v", err)
	}

	// Load vkey.json
	vkData, err := os.ReadFile(fmt.Sprintf("%s/vkey.json", circomDataDir))
	if err != nil {
		log.Fatalf("failed to read vkey: %v", err)
	}

	// Load public signals
	publicSignalsData, err := os.ReadFile(fmt.Sprintf("%s/public_signals.json", circomDataDir))
	if err != nil {
		log.Fatalf("failed to read public signals: %v", err)
	}

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

	fmt.Println("Verifying proof with Gnark verifier...")
	gnarkProof, err := parser.ConvertCircomToGnark(snarkProof, snarkVk, publicSignals)
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
	fmt.Println("Proof verification succeeded!")

	// Recursive proof verification
	fmt.Println("Now let's build a new circuit to verify the Circom proof recursively")

	// Get the recursion proof and placeholders
	recursionData, recursionPlaceholders, err := parser.ConvertCircomToGnarkRecursion(snarkProof, snarkVk, publicSignals)
	if err != nil {
		log.Fatalf("failed to convert Circom proof to Gnark recursion proof: %v", err)
	}

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

	// Check if we are running as a test
	if runtest {
		// Create the circuit assignment with actual values
		circuitAssignment := &VerifyCircomProofCircuit{
			Proof:        recursionData.Proof,
			VerifyingKey: recursionData.Vk,
			PublicInputs: recursionData.PublicInputs,
		}

		err = test.IsSolved(placeholderCircuit, circuitAssignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}
		return
	}

	// Check if the circuit files exist, else compile the circuit and write the files
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
		VerifyingKey: recursionData.Vk,
		PublicInputs: recursionData.PublicInputs,
	}

	// Create the witness
	startTime := time.Now()
	fmt.Println("Creating witness...")
	witnessFull, err := frontend.NewWitness(circuitAssignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		fmt.Printf("Failed to create witness: %v\n", err)
		return
	}
	fmt.Printf("Witness creation time: %v\n", time.Since(startTime))

	// Create the proofs for the aggregate recursion circuit
	aggregateProofCircuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		log.Fatalf("Failed to convert verification key to recursion verification key: %v", err)
	}
	aggregateCircuitData := &AggregateProofCircuit{
		VerifyingKey: aggregateProofCircuitVk,
	}
	for i := 0; i < 10; i++ {
		fmt.Printf("Creating proof %d...", i)
		startTime = time.Now()
		proof, err := groth16.Prove(ccs, pk, witnessFull)
		if err != nil {
			fmt.Printf("Proving failed: %v\n", err)
			return
		}
		fmt.Printf("Proving Recursion time: %v\n", time.Since(startTime))

		publicWitness, err := witnessFull.Public()
		if err != nil {
			log.Fatalf("Failed to create public witness: %v\n", err)
		}

		proofData := BatchProofData{}
		if proofData.PublicInputs, err = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](publicWitness); err != nil {
			log.Fatal(err)
		}
		if proofData.Proof, err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof); err != nil {
			log.Fatal(err)
		}
		aggregateCircuitData.Proofs[i] = proofData
	}

	// Generate the aggregation proof

	fmt.Println("Creating witness for final aggregation proof...")
	witnessFull2, err := frontend.NewWitness(aggregateCircuitData, ecc.BW6_761.ScalarField())
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	// Check if the circuit files exist, else compile the circuit and write the files
	ccs2, pk2, vk2, err := LoadCircuit(ecc.BW6_761, AggregateProofCircuitType)
	if err != nil {
		if errors.Is(err, ErrCircuitDoesNotExist) {
			// Files do not exist, compile the circuit
			fmt.Println("Compiling aggregate circuit...")
			// Create placeholder proofs
			placeHolderProofs := [10]BatchProofData{}
			for i := 0; i < 10; i++ {
				placeHolderProofs[i] = BatchProofData{
					Proof:        stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccs2),
					PublicInputs: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](ccs2),
				}
			}

			placeHolderAggregateCircuit := &AggregateProofCircuit{
				Proofs:       placeHolderProofs,
				VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](ccs2),
			}
			// Compile the circuit
			ccs2, pk2, vk2, err = CompileCircuit(placeHolderAggregateCircuit, ecc.BW6_761.ScalarField(), AggregateProofCircuitType)
			if err != nil {
				log.Fatalf("Failed to compile circuit: %v", err)
			}
		} else {
			log.Fatalf("Failed to load circuit: %v", err)
		}
	}

	fmt.Println("Creating final aggregation proof")
	startTime = time.Now()
	proof2, err := groth16.Prove(ccs2, pk2, witnessFull2)
	if err != nil {
		fmt.Printf("Proving failed: %v\n", err)
		return
	}
	fmt.Printf("Proving Recursion time: %v\n", time.Since(startTime))

	// Verify the proof
	publicWitness2, err := witnessFull2.Public()
	if err != nil {
		log.Fatalf("Failed to create public witness: %v", err)
	}
	fmt.Println("Verifying...")
	startTime = time.Now()
	err = groth16.Verify(proof2, vk2, publicWitness2)
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
	PublicInputs stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`
}

func (c *VerifyCircomProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.PublicInputs, stdgroth16.WithCompleteArithmetic())
}

// VerifyCircomProofCircuit is the circuit that verifies the Circom proof inside Gnark
type AggregateProofCircuit struct {
	Proofs       [10]BatchProofData
	VerifyingKey stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
}

type BatchProofData struct {
	Proof        stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	PublicInputs stdgroth16.Witness[sw_bls12377.ScalarField] `gnark:",public"`
}

func (c *AggregateProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	for i := 0; i < 10; i++ {
		if err := verifier.AssertProof(c.VerifyingKey, c.Proofs[i].Proof, c.Proofs[i].PublicInputs, stdgroth16.WithCompleteArithmetic()); err != nil {
			return fmt.Errorf("assert proof: %w", err)
		}
	}
	return nil
}
