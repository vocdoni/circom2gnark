package parser

import (
	"fmt"
	"math/big"
)

// stringToBigInt converts a string to a big.Int, handling both decimal and hexadecimal representations.
func stringToBigInt(s string) (*big.Int, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		bi, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil, fmt.Errorf("failed to parse hex string %s", s)
		}
		return bi, nil
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse decimal string %s", s)
	}
	return bi, nil
}

func addZPadding(b []byte) []byte {
	var z [32]byte
	var r []byte
	r = append(r, z[len(b):]...) // add padding on the left
	r = append(r, b...)
	return r[:32]
}

func stringToBytes(s string) ([]byte, error) {
	if s == "1" {
		s = "0"
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("error parsing bigint stringToBytes")
	}
	b := bi.Bytes()
	if len(b) != 32 { //nolint:gomnd
		b = addZPadding(b)
	}
	return b, nil
}
