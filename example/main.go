package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/circomgnark/parser"
)

func main() {
	runtest := false
	flag.BoolVar(&runtest, "test", false, "Run as test")
	flag.Parse()
	// Load proof.json
	proofData, err := os.ReadFile("proof.json")
	if err != nil {
		log.Fatalf("failed to read proof: %v", err)
	}

	// Load vkey.json
	vkData, err := os.ReadFile("vkey.json")
	if err != nil {
		log.Fatalf("failed to read vkey: %v", err)
	}

	// Load public signals
	publicSignalsData, err := os.ReadFile("public_signals.json")
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

	// Create the circuit assignment with actual values
	circuitAssignment := &VerifyCircomProofCircuit{
		Proof:        recursionData.Proof,
		VerifyingKey: recursionData.Vk,
		PublicInputs: recursionData.PublicInputs,
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
