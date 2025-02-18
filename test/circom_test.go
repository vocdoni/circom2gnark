package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vocdoni/circom2gnark/parser"
)

func loadFile(t *testing.T, path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}

func unmarshalJSON(t *testing.T, data []byte) interface{} {
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	return out
}

func TestConversionRoundtrip(t *testing.T) {
	// Define the directory with the Circom files
	circomDir := "circom_data"

	// Load original files
	proofPath := filepath.Join(circomDir, "proof.json")
	vkeyPath := filepath.Join(circomDir, "vkey.json")
	publicSignalsPath := filepath.Join(circomDir, "public_signals.json")

	origProofData := loadFile(t, proofPath)
	origVkeyData := loadFile(t, vkeyPath)
	origPublicSignalsData := loadFile(t, publicSignalsPath)

	// Unmarshal originals into generic maps/slices for comparison
	origProofJSON := unmarshalJSON(t, origProofData)
	origVkeyJSON := unmarshalJSON(t, origVkeyData)
	origPublicSignalsJSON := unmarshalJSON(t, origPublicSignalsData)

	// Parse the original Circom objects.
	snarkProof, err := parser.UnmarshalCircomProofJSON(origProofData)
	if err != nil {
		t.Fatalf("failed to unmarshal proof: %v", err)
	}
	snarkVK, err := parser.UnmarshalCircomVerificationKeyJSON(origVkeyData)
	if err != nil {
		t.Fatalf("failed to unmarshal verification key: %v", err)
	}
	publicSignals, err := parser.UnmarshalCircomPublicSignalsJSON(origPublicSignalsData)
	if err != nil {
		t.Fatalf("failed to unmarshal public signals: %v", err)
	}

	// Convert Circom objects to Gnark format.
	gnarkProof, err := parser.ConvertCircomToGnark(snarkVK, snarkProof, publicSignals)
	if err != nil {
		t.Fatalf("failed to convert Circom proof to Gnark proof: %v", err)
	}

	w, err := parser.PublicWitnessFromVector(gnarkProof.PublicInputs)
	if err != nil {
		t.Fatalf("failed to transform witness: %v", err)
	}

	// Now convert the Gnark proof back to Circom format.
	circomProof, circomVK, circomPublicSignals, err := parser.ConvertGnarkToCircom(
		gnarkProof.Proof,
		gnarkProof.VerifyingKey,
		w,
	)
	if err != nil {
		t.Fatalf("failed to convert Gnark proof back to Circom format: %v", err)
	}

	// Marshal back to JSON.
	regeneratedProofData, err := parser.MarshalCircomProofJSON(circomProof)
	if err != nil {
		t.Fatalf("failed to marshal regenerated proof: %v", err)
	}
	regeneratedVkeyData, err := parser.MarshalCircomVerificationKeyJSON(circomVK)
	if err != nil {
		t.Fatalf("failed to marshal regenerated verification key: %v", err)
	}
	regeneratedPublicSignalsData, err := parser.MarshalCircomPublicSignalsJSON(circomPublicSignals)
	if err != nil {
		t.Fatalf("failed to marshal regenerated public signals: %v", err)
	}

	// Unmarshal regenerated JSON.
	regeneratedProofJSON := unmarshalJSON(t, regeneratedProofData)
	regeneratedVkeyJSON := unmarshalJSON(t, regeneratedVkeyData)
	regeneratedPublicSignalsJSON := unmarshalJSON(t, regeneratedPublicSignalsData)

	// Compare the proof.
	if !reflect.DeepEqual(origProofJSON, regeneratedProofJSON) {
		t.Errorf("Proof mismatch:\nOriginal: %#v\nRegenerated: %#v", origProofJSON, regeneratedProofJSON)
	}

	// Compare the verification key.
	if !reflect.DeepEqual(origVkeyJSON, regeneratedVkeyJSON) {
		t.Errorf("Verification key mismatch:\nOriginal: %#v\nRegenerated: %#v", origVkeyJSON, regeneratedVkeyJSON)
	}

	// Compare the public signals.
	if !reflect.DeepEqual(origPublicSignalsJSON, regeneratedPublicSignalsJSON) {
		t.Errorf("Public signals mismatch:\nOriginal: %#v\nRegenerated: %#v", origPublicSignalsJSON, regeneratedPublicSignalsJSON)
	}
}
