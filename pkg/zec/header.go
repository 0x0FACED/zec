package zec

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"strings"
	"time"

	"github.com/0x0FACED/uuid"
)

const (
	// bytes
	HEADER_SIZE = 256
)

// 256 bytes
type Header struct {
	Version          uint8    // 1 byte — file version (0x01)
	Flags            uint8    // 1 byte — flags
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
	IndexTableNonce  [12]byte // 12 bytes — nonce for enc index table
	Reserved         [60]byte // 60 bytes — for future use
}

func NewHeader(opts ContainerOptions) (*Header, error) {
	salt, err := GenerateSalt16()
	if err != nil {
		return nil, err
	}

	indexNonce, err := GenerateNonce12()
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	return &Header{
		Version:          1,
		Flags:            0,
		EncryptionAlgo:   1, // ChaCha20
		ArgonMemoryLog2:  uint8(bits.Len32(opts.ArgonMemory) - 1),
		SecretCount:      0,
		CreatedAt:        now,
		ModifiedAt:       now,
		DataSize:         0,
		OwnerID:          uuid.NewV4(),
		ArgonSalt:        salt,
		ArgonIterations:  opts.ArgonIterations,
		ArgonParallelism: opts.ArgonParallelism,
		IndexTableOffset: HEADER_SIZE,
		IndexTableNonce:  indexNonce,
	}, nil
}

// AuthenticatedBytes serialize struct Header to byte arr.
// Checksum, Complete Flag NOT included.
func (h *Header) AuthenticatedBytes() []byte {
	buf := bytes.NewBuffer(nil)

	buf.WriteByte(h.Version)
	buf.WriteByte(h.EncryptionAlgo)
	buf.WriteByte(h.ArgonMemoryLog2)
	binary.Write(buf, binary.LittleEndian, h.SecretCount)
	binary.Write(buf, binary.LittleEndian, h.CreatedAt)
	binary.Write(buf, binary.LittleEndian, h.ModifiedAt)
	binary.Write(buf, binary.LittleEndian, h.DataSize)
	buf.Write(h.OwnerID[:])   // 16 bytes
	buf.Write(h.ArgonSalt[:]) // 16 bytes
	binary.Write(buf, binary.LittleEndian, h.ArgonIterations)
	buf.WriteByte(h.ArgonParallelism)
	buf.WriteByte(1)             // Padding byte
	buf.Write(h.EncryptedFEK[:]) // 60 bytes
	binary.Write(buf, binary.LittleEndian, h.IndexTableOffset)
	buf.Write(h.IndexTableNonce[:]) // 12 bytes
	buf.Write(h.Reserved[:])        // 60 bytes

	return buf.Bytes()
}

var FlagNames = map[uint8]string{
	FlagUndefined:  "U",
	FlagCompleted:  "C",
	FlagEncrypted:  "E",
	FlagCompressed: "X",
	FlagDeleted:    "D",
}

// move to func
func (h *Header) FlagsString() string {
	var flags []string
	for flag, name := range FlagNames {
		if h.Flags&flag != 0 { // flag is setted
			flags = append(flags, name)
		}
	}

	return strings.Join(flags, "|")
}
