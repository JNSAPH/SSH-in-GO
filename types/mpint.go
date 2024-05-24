package types

import (
	"math/big"
)

type MPINT struct {
	Length int
	Value  *big.Int
}

func ParseMPInt(data []byte) MPINT {
	if len(data) == 0 {
		return MPINT{Length: 0, Value: big.NewInt(0)}
	}
	// Check for negative number (MSB set)
	negative := data[0]&0x80 != 0
	if negative {
		// Two's complement conversion for negative numbers
		value := new(big.Int).SetBytes(data)
		twosComplement := new(big.Int).Sub(value, new(big.Int).Lsh(big.NewInt(1), uint(len(data)*8)))
		return MPINT{Length: len(data), Value: twosComplement}
	}
	// Positive number
	return MPINT{Length: len(data), Value: new(big.Int).SetBytes(data)}
}

func ConstructMPInt(value *big.Int) []byte {
	if value.Cmp(big.NewInt(0)) == 0 {
		return []byte{}
	}

	// Convert integer to bytes, big-endian
	byteValue := value.Bytes()

	// Ensure the format
	if value.Sign() > 0 && byteValue[0]&0x80 != 0 {
		return append([]byte{0x00}, byteValue...)
	}
	return byteValue
}
