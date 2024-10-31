// Package parser provides functions to parse Circom/SnarkJS Groth16 proofs
// and verification keys and convert them into Gnark-compatible structures for verification.
package parser

import (
	"encoding/json"
	"fmt"
)

// UnmarshalCircomProofJSON parses the JSON-encoded proof data into a SnarkJSProof struct.
func UnmarshalCircomProofJSON(data []byte) (*CircomProof, error) {
	var proof CircomProof
	err := json.Unmarshal(data, &proof)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proof JSON: %v", err)
	}
	return &proof, nil
}

// UnmarshalCircomVerificationKeyJSON parses the JSON-encoded verification key data into a SnarkJSVerificationKey struct.
func UnmarshalCircomVerificationKeyJSON(data []byte) (*CircomVerificationKey, error) {
	var vk CircomVerificationKey
	err := json.Unmarshal(data, &vk)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verification key JSON: %v", err)
	}
	return &vk, nil
}

// UnmarshalCircomPublicSignalsJSON parses the JSON-encoded public signals data into a slice of strings.
func UnmarshalCircomPublicSignalsJSON(data []byte) ([]string, error) {
	// Parse public signals
	var publicSignals []string
	if err := json.Unmarshal(data, &publicSignals); err != nil {
		return nil, fmt.Errorf("error parsing public signals: %w", err)
	}
	return publicSignals, nil
}
