package types

import "errors"

// fixed size secret metadata structure
type SecretMeta struct {
	ID         [16]byte // 16 bytes, secret ID (name or uuid). if name not provided - use uuid (not good)
	Offset     uint64   // 8 bytes, offset of the secret in the file
	Size       uint64   // 8 bytes, size of the secret
	CreatedAt  uint64   // 8 bytes, time of creation (unix)
	ModifiedAt uint64   // 8 bytes, time of last modification (unix)
	Type       uint8    // secret type (0x01 — file, 0x02 — text, 0x03 — binary for example)
	Flags      uint8    // bit flags (0x01 — encrypted, 0x02 — compressed, 0x04 — deleted for example)
	Reserved   [14]byte // reserved for future use (22 bytes)
}

func NewSecretMeta(id string, size uint64) (SecretMeta, error) {
	idBytes, err := stringToBytes(id)
	if err != nil {
		return SecretMeta{}, err
	}

	meta := SecretMeta{
		ID:         idBytes,
		Offset:     0,
		Size:       size,
		CreatedAt:  0,
		ModifiedAt: 0,
		Type:       0x01,
		Flags:      0x01,
		Reserved:   [14]byte{},
	}

	return meta, nil
}

func (sm *SecretMeta) SetOffset(offset uint64) {
	sm.Offset = offset
}

func (sm *SecretMeta) SetSize(size uint64) {
	sm.Size = size
}

func stringToBytes(s string) ([16]byte, error) {
	if len(s) > 16 {
		return [16]byte{}, errors.New("id size exceeded")
	}

	res := [16]byte{}
	copy(res[:], s)

	return res, nil
}
