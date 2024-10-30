package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"github.com/vocdoni/circomgnark/parser"
)

func init() {
	logger.Logger().Level(zerolog.DebugLevel)
}

func main() {
	runtest := false
	flag.BoolVar(&runtest, "test", false, "Run as test")
	flag.Parse()
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

	/*
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
	*/

	// CREATE THE WITNESS

	// Inside your main function or appropriate scope
	// Create a new witness
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Error creating witness: %v\n", err)
		return
	}

	// Total number of public variables, including one wire
	nbPublic := len(gnarkVk.G1.K)

	// Create a channel to send the public input values
	values := make(chan any, nbPublic)

	fmt.Printf("filling witness with %d public inputs\n", len(publicInputs))

	go func() {
		// Send the one wire value (1) first
		//one := fr_bn254.One()
		//values <- one

		// Then send the public inputs
		for i, input := range publicInputs {
			fmt.Printf("Sending public input %d: %v\n", i+1, input)
			values <- input
		}
		close(values)
	}()

	// Fill the witness
	err = w.Fill(len(publicInputs), 0, values)
	if err != nil {
		fmt.Printf("Error filling witness: %v\n", err)
		return
	}
	fmt.Printf("Witness filled with %d public inputs\n", len(publicInputs))

	// Now, create the recursion public inputs
	recursionPublicInputs, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](w)
	if err != nil {
		fmt.Printf("Error creating recursion public inputs: %v\n", err)
		return
	}

	// Step 2: Create placeholder verifying key
	/*	placeholderVk := stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
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
	*/

	placeholderVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
	if err != nil {
		fmt.Printf("Failed to convert verification key to recursion verification key: %v\n", err)
		return
	}
	placeholderVk.G1.K = make([]sw_bn254.G1Affine, len(placeholderVk.G1.K))

	// Step 3: Create placeholder witness
	placeholderWitness := stdgroth16.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], len(publicInputs)),
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

	// Initialize variables for ccs, pk, vk
	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	// Check if we are running as a test
	if runtest {
		// Create the circuit assignment with actual values
		circuitAssignment := &VerifyCircomProofCircuit{
			Proof:        recursionProof,
			VerifyingKey: recursionVk,
			PublicInputs: recursionPublicInputs,
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
		Proof:        recursionProof,
		VerifyingKey: recursionVk,
		PublicInputs: recursionPublicInputs,
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

	// Load circuit
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
	fmt.Println("Loaded circuit from circuit.r1cs")

	// Load proving key
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
	fmt.Println("Loaded proving key from pk.bin")

	// Load verifying key
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
	fmt.Println("Loaded verifying key from vk.bin")

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
