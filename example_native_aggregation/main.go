package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	runtest := false
	circomDataDir := "circom_data"
	flag.BoolVar(&runtest, "test", false, "Run as test")
	flag.StringVar(&circomDataDir, "circom-data", "circom_data", "Directory containing the Circom JSON data files")
	flag.Parse()

	// Load Circom proof.json
	proofData, err := os.ReadFile(fmt.Sprintf("%s/proof.json", circomDataDir))
	if err != nil {
		log.Fatalf("failed to read proof: %v", err)
	}

	// Load Circom vkey.json
	vkData, err := os.ReadFile(fmt.Sprintf("%s/vkey.json", circomDataDir))
	if err != nil {
		log.Fatalf("failed to read vkey: %v", err)
	}

	// Load Circom public signals
	publicSignalsData, err := os.ReadFile(fmt.Sprintf("%s/public_signals.json", circomDataDir))
	if err != nil {
		log.Fatalf("failed to read public signals: %v", err)
	}

	// Generate the first proof, from bn254/Circom to bls12377/Gnark using emulated arithmetic
	proof, vk, wit, ccs := circom2gnarkRecursiveBls12377(proofData, vkData, publicSignalsData, runtest)

	// Generate the second proof, from bls12377/Gnark (multiple) to bw6_761/Gnark using native arithmetic
	var proofs []*innerProof
	proofs = append(proofs, &innerProof{p: proof, w: wit})

	log.Println("Aggregating proofs...")
	if err := AggregateProofs(proofs, vk, ccs); err != nil {
		log.Fatalf("failed to aggregate proofs: %v", err)
	}
}
