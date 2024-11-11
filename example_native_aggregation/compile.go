package main

import (
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// circuitType is an enum of the different types of circuits
type circuitType int

const (
	// VerifyCircomProofCircuitType is the circuit that verifies the Circom proof inside Gnark
	VerifyCircomProofCircuitType circuitType = iota
	// AggregateProofCircuitType is the circuit that verifies the Circom proof inside Gnark
	AggregateProofCircuitType
)

var ErrCircuitDoesNotExist = fmt.Errorf("circuit does not exist")

// CompileCircuit compiles the circuit, generates the proving and verifying keys, and writes them to files
func CompileCircuit(placeholdercircuit any, scalarField *big.Int, t circuitType) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var err error
	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var fileSuffix string
	var circuit frontend.Circuit

	switch t {
	case VerifyCircomProofCircuitType:
		circuit = placeholdercircuit.(*VerifyCircomProofCircuit)
		fileSuffix = "verify"
	case AggregateProofCircuitType:
		circuit = placeholdercircuit.(*AggregateProofCircuit)
		fileSuffix = "aggregate"
	default:
		return nil, nil, nil, fmt.Errorf("unknown circuit type")
	}

	startTime := time.Now()
	ccs, err = frontend.Compile(scalarField, r1cs.NewBuilder, circuit)
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
	pkFile, err := os.Create(fmt.Sprintf("pk_%s.bin", fileSuffix))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating pk.bin: %w", err)
	}
	defer pkFile.Close()
	_, err = pk.WriteTo(pkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error writing proving key to pk.bin: %w", err)
	}

	// Write verifying key to a file
	vkFile, err := os.Create(fmt.Sprintf("vk_%s.bin", fileSuffix))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating vk.bin: %w", err)
	}
	defer vkFile.Close()
	_, err = vk.WriteRawTo(vkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error writing verifying key to vk.bin: %w", err)
	}

	// Write circuit to a file
	circuitFile, err := os.Create(fmt.Sprintf("circuit_%s.r1cs", fileSuffix))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating circuit.r1cs: %w", err)
	}
	defer circuitFile.Close()
	_, err = ccs.WriteTo(circuitFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error writing circuit to circuit.r1cs: %w", err)
	}

	return ccs, pk, vk, nil
}

// LoadCircuit loads the circuit, proving key, and verifying key from files.
// It returns the constraint system, proving key, and verifying key.
// If the files do not exist, it returns ErrCircuitDoesNotExist.
func LoadCircuit(curve ecc.ID, t circuitType) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var err error
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	var fileSuffix string
	switch t {
	case VerifyCircomProofCircuitType:
		fileSuffix = "verify"
	case AggregateProofCircuitType:
		fileSuffix = "aggregate"
	default:
		return nil, nil, nil, fmt.Errorf("unknown circuit type")
	}

	startTime := time.Now()

	// Load circuit
	if _, err := os.Stat(fmt.Sprintf("circuit_%s.r1cs", fileSuffix)); err != nil {
		return nil, nil, nil, ErrCircuitDoesNotExist
	}

	fmt.Println("Loading circuit...")
	circuitFile, err := os.Open(fmt.Sprintf("circuit_%s.r1cs", fileSuffix))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening circuit.r1cs: %w", err)
	}
	defer circuitFile.Close()

	ccs := groth16.NewCS(curve)
	_, err = ccs.ReadFrom(circuitFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading circuit from circuit.r1cs: %w", err)
	}

	// Load proving key
	fmt.Println("Loading proving key...")
	pkFile, err := os.Open(fmt.Sprintf("pk_%s.bin", fileSuffix))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening pk.bin: %w", err)
	}
	defer pkFile.Close()
	pk = groth16.NewProvingKey(curve)

	_, err = pk.UnsafeReadFrom(pkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading proving key from pk.bin: %w", err)
	}

	// Load verifying key
	fmt.Println("Loading verifying key...")
	vkFile, err := os.Open(fmt.Sprintf("vk_%s.bin", fileSuffix))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening vk.bin: %w", err)
	}
	defer vkFile.Close()
	vk = groth16.NewVerifyingKey(curve)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading verifying key from vk.bin: %w", err)
	}

	fmt.Printf("Loading artifacts total time: %v\n", time.Since(startTime))
	return ccs, pk, vk, nil
}
