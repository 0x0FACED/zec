package crypto

import (
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	// all fields have int type, because its just comfortably
	Iterations  int
	MemoryLog   int
	Parallelism int
}

type KeyManager struct {
	masterKey *memguard.LockedBuffer
}

func NewKeyManager(rawPass []byte, salt [16]byte, params Argon2Params) *KeyManager {
	key := argon2idMasterKey32(rawPass, salt, uint8(params.MemoryLog), uint16(params.Iterations), uint8(params.Parallelism))
	locked := memguard.NewBufferFromBytes(key)
	return &KeyManager{
		masterKey: locked,
	}
}

func (km *KeyManager) MasterKey32() []byte {
	return km.masterKey.Data()
}

func (km *KeyManager) Close() {
	km.masterKey.Destroy()
}

// argon2idMasterKey32 returns 256 bit master key generated from password
// with provided argon2 parameters.
func argon2idMasterKey32(password []byte, salt [16]byte, memoryLog2 uint8, iterations uint16, parallelism uint8) []byte {
	memory := 1 << memoryLog2
	masterKey := argon2.IDKey(password, salt[:], uint32(iterations), uint32(memory), uint8(parallelism), 32)
	return masterKey
}
