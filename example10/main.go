package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
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

	// Load verification key (same for all proofs)
	vkData, err := os.ReadFile(fmt.Sprintf("%s/ballot_proof_test_vkey.json", circomDataDir))
	if err != nil {
		log.Fatalf("failed to read verification key: %v", err)
	}

	// Unmarshal the verification key
	snarkVk, err := parser.UnmarshalCircomVerificationKeyJSON(vkData)
	if err != nil {
		log.Fatalf("failed to unmarshal verification key: %v", err)
	}

	// Convert the verification key to Gnark format
	gnarkVk, err := parser.ConvertVerificationKey(snarkVk)
	if err != nil {
		log.Fatalf("failed to convert verification key: %v", err)
	}

	// Transform the verification key to recursion format
	recursionVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
	if err != nil {
		log.Fatalf("failed to convert verification key to recursion format: %v", err)
	}

	// Initialize variables
	var ballotProofs [10]BallotProof

	for i := 1; i <= 10; i++ {
		// Load proof
		proofFile := fmt.Sprintf("%s/%d_proof.json", circomDataDir, i)
		proofData, err := os.ReadFile(proofFile)
		if err != nil {
			log.Fatalf("failed to read proof %d: %v", i, err)
		}

		// Load public signals
		publicSignalsFile := fmt.Sprintf("%s/%d_pub_signals.json", circomDataDir, i)
		publicSignalsData, err := os.ReadFile(publicSignalsFile)
		if err != nil {
			log.Fatalf("failed to read public signals %d: %v", i, err)
		}

		// Unmarshal proof and public signals
		snarkProof, err := parser.UnmarshalCircomProofJSON(proofData)
		if err != nil {
			log.Fatalf("failed to unmarshal proof %d: %v", i, err)
		}

		publicSignals, err := parser.UnmarshalCircomPublicSignalsJSON(publicSignalsData)
		if err != nil {
			log.Fatalf("failed to unmarshal public signals %d: %v", i, err)
		}

		// Convert proof and public inputs to recursion types
		recursionData, _, err := parser.ConvertCircomToGnarkRecursion(snarkProof, snarkVk, publicSignals)
		if err != nil {
			log.Fatalf("failed to convert Circom proof to Gnark recursion proof %d: %v", i, err)
		}

		// Assign to ballotProofs array
		ballotProofs[i-1] = BallotProof{
			Proof:        recursionData.Proof,
			PublicInputs: recursionData.PublicInputs,
		}

		// Optionally, verify the proof outside the circuit
		gnarkProof, err := parser.ConvertCircomToGnark(snarkProof, snarkVk, publicSignals)
		if err != nil {
			log.Fatalf("failed to convert Circom proof to Gnark proof %d: %v", i, err)
		}
		verified, err := parser.VerifyProof(gnarkProof)
		if err != nil {
			log.Fatalf("failed to verify proof %d: %v", i, err)
		}
		if !verified {
			log.Fatalf("proof %d verification failed", i)
		}
		fmt.Printf("Proof %d verification succeeded!\n", i)
	}

	// Create the circuit assignment with actual values
	circuitAssignment := &VerifyCircomProofCircuit{
		VerifyingKey: recursionVk,
		BallotProofs: ballotProofs,
	}

	// Create placeholder proofs and public inputs
	var placeholderBallotProofs [10]BallotProof
	// Determine the number of public inputs
	numPublicInputs := len(recursionVk.G1.K) - 1 // Exclude the one wire
	for i := 0; i < 10; i++ {
		placeholderBallotProofs[i] = BallotProof{
			Proof: stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{},
			PublicInputs: stdgroth16.Witness[sw_bn254.ScalarField]{
				Public: make([]emulated.Element[sw_bn254.ScalarField], numPublicInputs),
			},
		}
	}

	// Create placeholder verification key
	placeholderVk := stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		G1: struct{ K []sw_bn254.G1Affine }{
			K: make([]sw_bn254.G1Affine, len(recursionVk.G1.K)),
		},
		G2: struct {
			GammaNeg, DeltaNeg sw_bn254.G2Affine
		}{},
		E:                            sw_bn254.GTEl{},
		CommitmentKeys:               nil,
		PublicAndCommitmentCommitted: nil,
	}
	// Initialize placeholder G1.K elements with dummy values
	for i := range placeholderVk.G1.K {
		placeholderVk.G1.K[i] = sw_bn254.G1Affine{}
	}

	// Create placeholder circuit
	placeholderCircuit := &VerifyCircomProofCircuit{
		VerifyingKey: placeholderVk,
		BallotProofs: placeholderBallotProofs,
	}

	// Initialize variables for ccs, pk, vk
	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	// Check if we are running as a test
	if runtest {
		err = test.IsSolved(placeholderCircuit, circuitAssignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}
		return
	}

	// Check if the files exist
	if _, err := os.Stat("pk.bin"); err == nil {
		// Files exist, load them
		fmt.Println("Found existing pk.bin, vk.bin, and circuit.r1cs. Loading them...")
		ccs, pk, vk, err = LoadCircuit()
		if err != nil {
			fmt.Printf("Failed to load circuit: %v\n", err)
			return
		}
	} else {
		// Files do not exist, compile the circuit
		fmt.Println("Compiling circuit...")
		ccs, pk, vk, err = CompileCircuit(placeholderCircuit)
		if err != nil {
			fmt.Printf("Failed to compile circuit: %v\n", err)
			return
		}
	}

	// Create the witness
	startTime := time.Now()
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

	// Create the proof
	fmt.Println("Proving...")
	startTime = time.Now()
	proof, err := groth16.Prove(
		ccs,
		pk,
		witnessFull,
		backend.WithIcicleAcceleration(),
	)
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

// CompileCircuit compiles the circuit, generates the proving and verifying keys, and writes them to files
func CompileCircuit(placeholderCircuit *VerifyCircomProofCircuit) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var err error
	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	startTime := time.Now()
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, placeholderCircuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile failed: %w", err)
	}
	fmt.Printf("Compilation time: %v\n", time.Since(startTime))

	// Generate the proving and verifying keys
	startTime = time.Now()
	fmt.Println("Setting up proving and verifying keys...")
	pk, vk, err = groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup failed: %w", err)
	}
	fmt.Printf("Setup time: %v\n", time.Since(startTime))

	// Write the proving key to a file
	pkFile, err := os.Create("pk.bin")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating pk.bin: %w", err)
	}
	defer pkFile.Close()
	_, err = pk.WriteTo(pkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error writing proving key to pk.bin: %w", err)
	}
	fmt.Println("Wrote proving key to pk.bin")

	// Write verifying key to a file
	vkFile, err := os.Create("vk.bin")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating vk.bin: %w", err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error writing verifying key to vk.bin: %w", err)
	}
	fmt.Println("Wrote verifying key to vk.bin")

	// Write circuit to a file
	circuitFile, err := os.Create("circuit.r1cs")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating circuit.r1cs: %w", err)
	}
	defer circuitFile.Close()
	_, err = ccs.WriteTo(circuitFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error writing circuit to circuit.r1cs: %w", err)
	}
	fmt.Println("Wrote circuit to circuit.r1cs")

	return ccs, pk, vk, nil
}

// LoadCircuit loads the circuit, proving key, and verifying key from files
func LoadCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var err error
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	startTime := time.Now()

	// Load circuit
	fmt.Println("Loading circuit...")
	circuitFile, err := os.Open("circuit.r1cs")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening circuit.r1cs: %w", err)
	}
	defer circuitFile.Close()

	ccs := groth16.NewCS(ecc.BN254)
	_, err = ccs.ReadFrom(circuitFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading circuit from circuit.r1cs: %w", err)
	}

	// Load proving key
	fmt.Println("Loading proving key...")
	pkFile, err := os.Open("pk.bin")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening pk.bin: %w", err)
	}
	defer pkFile.Close()
	pk = groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading proving key from pk.bin: %w", err)
	}

	// Load verifying key
	fmt.Println("Loading verifying key...")
	vkFile, err := os.Open("vk.bin")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening vk.bin: %w", err)
	}
	defer vkFile.Close()
	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading verifying key from vk.bin: %w", err)
	}

	fmt.Printf("Loading artifacts total time: %v\n", time.Since(startTime))
	return ccs, pk, vk, nil
}

// BallotProof represents a proof and its public inputs
type BallotProof struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	PublicInputs stdgroth16.Witness[sw_bn254.ScalarField]
}

// VerifyCircomProofCircuit is the circuit that verifies multiple Circom proofs inside Gnark
type VerifyCircomProofCircuit struct {
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] // private input
	BallotProofs [10]BallotProof                                                              `gnark:",public"`
}

func (c *VerifyCircomProofCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	for i := 0; i < 10; i++ {
		err := verifier.AssertProof(c.VerifyingKey, c.BallotProofs[i].Proof, c.BallotProofs[i].PublicInputs, stdgroth16.WithCompleteArithmetic())
		if err != nil {
			return fmt.Errorf("proof %d verification failed: %w", i+1, err)
		}
	}
	return nil
}
