package updater

// Disposable SendBeam test-signing credentials (SEC01).
//
// Generated with crypto/rand and cryptographically independent of every
// production key. The retired fixture seed removed by SEC01 derived the
// production update-signing trust anchor; these vectors must never do so.
// CI rejects production-bound signing credentials in test code.
const (
	sec01TestSeed = "637f66615835455f60151028b133953efc0ef53bcd54ffd188d78d27ab1774fe"
	sec01TestPub  = "RWTHcEwvDBxfq8P5KnT5qyaUZcVr8AdJrDPuJfXtuNTk9YZ+cDl6f90H" // 42-byte "Ed"+keyID+pub encoding; parses via ParseMinisignPublicKey
)
