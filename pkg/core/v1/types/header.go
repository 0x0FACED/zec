package types

const (
	// bytes
	HEADER_SIZE = 256
)

// 256 bytes
type Header struct {
	Version          uint8    // 1 byte — file version (0x01)
	CompleteFlag     uint8    // 1 byte — did write complete
	EncryptionAlgo   uint8    // 1 byte — ecnryption algorithm
	ArgonMemoryLog2  uint8    // 1 byte — log2(memory in KB) for Argon2
	SecretCount      uint32   // 4 bytes — secret count
	CreatedAt        int64    // 8 bytes — time of creation
	ModifiedAt       int64    // 8 bytes — time of last modification
	DataSize         uint64   // 8 bytes — size of the data (playload)
	OwnerID          [16]byte // 16 bytes —  uuid of the owner
	ArgonSalt        [16]byte // 16 bytes — Argon2 salt
	ArgonIterations  uint16   // 2 bytes — Argon2 iterations
	ArgonParallelism uint8    // 1 byte — Argon2 parallelism
	_                uint8    // 1 byte — padding between nonce and checksum
	Checksum         [32]byte // 32 bytes — checksum of the file (sha256)
	VerificationTag  [16]byte // 16 bytes — HMAC(master_key, "zec-verification")[:16]
	EncryptedFEK     [60]byte // 60 bytes — nonce (12) + ciphertext (32) + tag (16)
	IndexTableOffset uint64   // 8 bytes — offset of the index table
	Reserved         [72]byte // 72 bytes — for future use
}
