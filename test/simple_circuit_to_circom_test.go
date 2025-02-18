package test

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/vocdoni/circom2gnark/parser"
)

func TestExponentiateToCircom(t *testing.T) {
	// Our simple circuit: y == x^e
	// We'll use a valid assignment: X=2, E=12, Y=4096.
	var circuit Circuit
	assignment := Circuit{
		X: 2,
		E: 12,
		Y: 4096,
	}

	// Compile the circuit.
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("failed to compile circuit: %v", err)
	}
	t.Logf("Circuit compiled with %d constraints", cs.GetNbConstraints())

	// Setup: generate proving and verifying keys.
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("groth16 setup failed: %v", err)
	}

	// Create full witness from the assignment.
	witnessFull, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("failed to create witness: %v", err)
	}

	// Extract public witness.
	publicWitness, err := witnessFull.Public()
	if err != nil {
		t.Fatalf("failed to get public witness: %v", err)
	}

	// Create the Groth16 proof.
	proof, err := groth16.Prove(cs, pk, witnessFull)
	if err != nil {
		t.Fatalf("groth16 proving failed: %v", err)
	}

	// Verify the proof with Gnark.
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		t.Fatalf("groth16 proof verification failed: %v", err)
	}
	t.Log("Proof verification succeeded!")

	// --- Conversion to Circom format ---

	// Convert the Gnark proof into Circom-compatible objects.
	circomProof, circomVk, circomPub, err := parser.ConvertGnarkToCircom(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("conversion to Circom format failed: %v", err)
	}

	// Marshal the Circom objects to JSON.
	proofJSON, err := parser.MarshalCircomProofJSON(circomProof)
	if err != nil {
		t.Fatalf("failed to marshal proof JSON: %v", err)
	}
	vkJSON, err := parser.MarshalCircomVerificationKeyJSON(circomVk)
	if err != nil {
		t.Fatalf("failed to marshal vk JSON: %v", err)
	}
	pubJSON, err := parser.MarshalCircomPublicSignalsJSON(circomPub)
	if err != nil {
		t.Fatalf("failed to marshal public signals JSON: %v", err)
	}

	// Write JSON files to a temporary directory.
	tempDir, err := os.MkdirTemp("", "circom_json")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	t.Logf("Writing Circom JSON files to %s", tempDir)

	if err := os.WriteFile(tempDir+"/proof.json", proofJSON, 0644); err != nil {
		t.Fatalf("failed to write proof.json: %v", err)
	}
	if err := os.WriteFile(tempDir+"/vkey.json", vkJSON, 0644); err != nil {
		t.Fatalf("failed to write vkey.json: %v", err)
	}
	if err := os.WriteFile(tempDir+"/public_signals.json", pubJSON, 0644); err != nil {
		t.Fatalf("failed to write public_signals.json: %v", err)
	}

	t.Logf("Test files written to %s", tempDir)
	t.Logf("To verify manually run: snarkjs groth16 verify %s/vkey.json %s/public_signals.json %s/proof.json",
		tempDir, tempDir, tempDir,
	)

	ok, err := parser.VerifyCircomProof(tempDir+"/proof.json", tempDir+"/vkey.json", tempDir+"/public_signals.json")
	if err != nil {
		t.Fatalf("failed to verify Circom proof: %v", err)
	}
	if !ok {
		t.Fatal("Circom proof verification failed")
	}
}

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type Circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(api frontend.API) error {

	// number of bits of exponent
	const bitSize = 8

	// specify constraints
	output := frontend.Variable(1)
	bits := bits.ToBinary(api, circuit.E, bits.WithNbDigits(bitSize))

	for i := 0; i < len(bits); i++ {
		if i != 0 {
			output = api.Mul(output, output)
		}
		multiply := api.Mul(output, circuit.X)
		output = api.Select(bits[len(bits)-1-i], multiply, output)

	}

	api.AssertIsEqual(circuit.Y, output)

	return nil
}
