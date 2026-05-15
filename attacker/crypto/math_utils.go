package crypto

import (
	"math/big"
)

// Attack range boundary definition
type AttackInterval struct {
	Start, End *big.Int
}

// Calculate ceiling division result
func CeilDiv(dividend, divisor *big.Int) *big.Int {
	quotient := new(big.Int).Div(dividend, divisor)
	remainder := new(big.Int).Mod(dividend, divisor)
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

// Calculate floor division result
func FloorDiv(dividend, divisor *big.Int) *big.Int {
	return new(big.Int).Div(dividend, divisor)
}
