package types

// fixed size secret metadata structure
type SecretMeta struct {
	ID         [16]byte // 16 bytes, secret ID (UUID)
	Offset     uint64   // 8 bytes, offset of the secret in the file
	Size       uint64   // 8 bytes, size of the secret
	CreatedAt  uint64   // 8 bytes, time of creation (unix)
	ModifiedAt uint64   // 8 bytes, time of last modification (unix)
	Type       uint8    // secret type (0x01 — file, 0x02 — text, 0x03 — binary for example)
	Flags      uint8    // bit flags (0x01 — encrypted, 0x02 — compressed, 0x04 — deleted for example)
	Reserved   [22]byte // reserved for future use (22 bytes)
}
