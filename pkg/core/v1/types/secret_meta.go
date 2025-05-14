package types

import (
	"errors"
	"strings"
)

const (
	PlainText = 0x01
	File      = 0x02
)

const (
	AEAD      = 0x01
	Streaming = 0x02
)

// fixed size secret metadata structure
// 94 bytes
type SecretMeta struct {
	// UUID is not used. flag --name is required
	Name        [32]byte // 32 bytes, secret ID (name or uuid). if name not provided - use uuid (not good)
	Offset      uint64   // 8 bytes, offset of the secret in the file
	Size        uint64   // 8 bytes, size of the secret
	CreatedAt   uint64   // 8 bytes, time of creation (unix)
	ModifiedAt  uint64   // 8 bytes, time of last modification (unix)
	Type        uint8    // 1 byte, secret type (0x01 — file, 0x02 — text, 0x03 — binary for example)
	Flags       uint8    // 1 byte, bit flags (0x01 — encrypted, 0x02 — compressed, 0x04 — deleted for example)
	_           [1]byte  // padding
	Nonce       [24]byte // 24 bytes, iv for encryption (chacha20[:12] xchacha20[:],  or aes-gcm[:12])
	EncryptMode uint8    // 1 byte, AEAD or Streaming chacha20
}

// NewSecretMeta used for plain text
func NewSecretMeta(id string, size uint64) (SecretMeta, error) {
	idBytes, err := stringToBytes(id)
	if err != nil {
		return SecretMeta{}, err
	}

	meta := SecretMeta{
		Name:       idBytes,
		Offset:     0,
		Size:       size,
		CreatedAt:  0,
		ModifiedAt: 0,
		Type:       0x01,
		Flags:      0x01,
		Nonce:      [24]byte{},
	}

	return meta, nil
}

// NewSecretMetaWithType used for files
func NewSecretMetaWithType(id string, size uint64, _type uint8) (SecretMeta, error) {
	idBytes, err := stringToBytes(id)
	if err != nil {
		return SecretMeta{}, err
	}

	meta := SecretMeta{
		Name:       idBytes,
		Offset:     0,
		Size:       size,
		CreatedAt:  0,
		ModifiedAt: 0,
		Type:       _type,
		Flags:      0x01,
		Nonce:      [24]byte{},
	}

	return meta, nil
}

func (sm SecretMeta) TypeString() string {
	switch sm.Type {
	case PlainText:
		return "Text"
	case File:
		return "File"
	default:
		return "Unknown"
	}
}

func (sm SecretMeta) EncryptModeString() string {
	switch sm.EncryptMode {
	case AEAD:
		return "AEAD"
	case Streaming:
		return "Streaming"
	default:
		return "Unknown"
	}
}

// move to func
func (meta *SecretMeta) FlagsString() string {
	var flags []string
	for flag, name := range FlagNames {
		if meta.Flags&flag != 0 { // flag is setted
			flags = append(flags, name)
		}
	}

	return strings.Join(flags, "|")
}

func (sm *SecretMeta) SetOffset(offset uint64) {
	sm.Offset = offset
}

func (sm *SecretMeta) SetSize(size uint64) {
	sm.Size = size
}

func stringToBytes(s string) ([32]byte, error) {
	if len(s) > 32 {
		return [32]byte{}, errors.New("name size must be less than 32 bytes")
	}

	res := [32]byte{}
	copy(res[:], s)

	return res, nil
}
