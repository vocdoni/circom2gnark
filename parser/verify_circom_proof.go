package parser

import (
	"os"

	"github.com/vocdoni/go-snark/parsers"
	"github.com/vocdoni/go-snark/verifier"
)

// VerifyCircomProof verifies a Circom proof using go-snark, which is a Go implementation of the Circom proof system.
// The parameters are the paths to the proof, verification key, and public signals JSON files.
// The function returns true if the proof is valid, false otherwise.
// An error is returned if there is a problem reading the files or parsing the JSON data.
func VerifyCircomProof(proofPath, verificationKeyPath, publicPath string) (bool, error) {
	proofJSON, err := os.ReadFile(proofPath) //nolint:gosec
	if err != nil {
		return false, err
	}
	vkJSON, err := os.ReadFile(verificationKeyPath) //nolint:gosec
	if err != nil {
		return false, err
	}
	publicJSON, err := os.ReadFile(publicPath) //nolint:gosec
	if err != nil {
		return false, err
	}

	public, err := parsers.ParsePublicSignals(publicJSON)
	if err != nil {
		return false, err
	}
	proof, err := parsers.ParseProof(proofJSON)
	if err != nil {
		return false, err
	}
	vk, err := parsers.ParseVk(vkJSON)
	if err != nil {
		return false, err
	}

	return verifier.Verify(vk, proof, public), nil
}
