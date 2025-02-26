package parser

import (
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi"

	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// ExportWitnessToSolidityInputs exports the public witness to a JSON file for Solidity.
func ExportWitnessToSolidityInputs(w witness.Witness, circuitAssignments frontend.Circuit, jsonOutputFilePath string) error {
	schema, err := frontend.NewSchema(circuitAssignments)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	publicWitness, err := w.Public()
	if err != nil {
		return fmt.Errorf("failed to extract public witness: %w", err)
	}
	jsonWitness, err := publicWitness.ToJSON(schema)
	if err != nil {
		return fmt.Errorf("failed to convert public witness to JSON: %w", err)
	}
	pubWitnessJSONfd, err := os.Create(jsonOutputFilePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer pubWitnessJSONfd.Close()
	_, err = pubWitnessJSONfd.Write(jsonWitness)
	if err != nil {
		return fmt.Errorf("failed to write public witness: %w", err)
	}
	return nil
}

//////////////////////

var (
	groth16CommitmentProofABI, _ = abi.NewType("tuple", "Groth16CommitmentProof", []abi.ArgumentMarshaling{
		{Name: "proof", Type: "uint256[8]"},
		{Name: "commitments", Type: "uint256[2]"},
		{Name: "commitment_pok", Type: "uint256[2]"},
	})
)

// SolidityProof represents a Groth16 proof for Solidity (without commitments).
type SolidityProof struct {
	Ar  [2]*big.Int    `json:"Ar"`
	Bs  [2][2]*big.Int `json:"Bs"`
	Krs [2]*big.Int    `json:"Krs"`
}

// Groth16CommitmentProof represents a Groth16 proof with commitments, for Solidity.
type Groth16CommitmentProof struct {
	Proof         SolidityProof `json:"proof"`
	Commitments   [2]*big.Int   `json:"commitments"`
	CommitmentPok [2]*big.Int   `json:"commitment_pok"`
}

// FromGnarkProof converts a gnark groth16 proof to a Solidity‑compatible proof.
func (p *Groth16CommitmentProof) FromGnarkProof(proof groth16.Proof) error {
	g16proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return fmt.Errorf("expected groth16_bn254.Proof, got %T", proof)
	}

	solProof := SolidityProof{
		Ar: [2]*big.Int{
			g16proof.Ar.X.BigInt(new(big.Int)),
			g16proof.Ar.Y.BigInt(new(big.Int)),
		},
		Bs: [2][2]*big.Int{
			{
				g16proof.Bs.X.A1.BigInt(new(big.Int)),
				g16proof.Bs.X.A0.BigInt(new(big.Int)),
			},
			{
				g16proof.Bs.Y.A1.BigInt(new(big.Int)),
				g16proof.Bs.Y.A0.BigInt(new(big.Int)),
			},
		},
		Krs: [2]*big.Int{
			g16proof.Krs.X.BigInt(new(big.Int)),
			g16proof.Krs.Y.BigInt(new(big.Int)),
		},
	}

	com := [2]*big.Int{
		g16proof.Commitments[0].X.BigInt(new(big.Int)),
		g16proof.Commitments[0].Y.BigInt(new(big.Int)),
	}

	comPok := [2]*big.Int{
		g16proof.CommitmentPok.X.BigInt(new(big.Int)),
		g16proof.CommitmentPok.Y.BigInt(new(big.Int)),
	}

	p.Proof = solProof
	p.Commitments = com
	p.CommitmentPok = comPok
	return nil
}

// ABIEncode encodes the Groth16CommitmentProof to an ABI‑encoded byte slice.
func (p *Groth16CommitmentProof) ABIEncode() ([]byte, error) {
	type abiProof struct {
		Proof         [8]*big.Int `json:"proof"`
		Commitments   [2]*big.Int `json:"commitments"`
		CommitmentPok [2]*big.Int `json:"commitment_pok"`
	}
	proof := [8]*big.Int{
		p.Proof.Ar[0],
		p.Proof.Ar[1],
		p.Proof.Bs[0][0],
		p.Proof.Bs[0][1],
		p.Proof.Bs[1][0],
		p.Proof.Bs[1][1],
		p.Proof.Krs[0],
		p.Proof.Krs[1],
	}

	proofABI := abiProof{
		Proof:         proof,
		Commitments:   p.Commitments,
		CommitmentPok: p.CommitmentPok,
	}
	packer := abi.Arguments{
		{Type: groth16CommitmentProofABI},
	}
	return packer.Pack(proofABI)
}
