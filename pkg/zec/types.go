package zec

import "time"

// SecretMeta метаданные секрета
type SecretMeta struct {
	Name        [32]byte
	Offset      uint64
	Size        uint64
	CreatedAt   uint64
	ModifiedAt  uint64
	Type        SecretType
	Flags       uint8
	_           uint8
	Nonce       [24]byte // максимальный размер для XChaCha20
	EncryptMode EncryptMode
}

// SecretOptions опции для операций с секретами
type SecretOptions struct {
	Type        SecretType
	EncryptMode EncryptMode
}

// For plain text or small files
func DefaultSecretOptions() *SecretOptions {
	return &SecretOptions{
		Type:        SecretTypeText,
		EncryptMode: EncryptModeChaCha20,
	}
}

// For files
func FileSecretOptions() *SecretOptions {
	return &SecretOptions{
		Type:        SecretTypeFile,
		EncryptMode: EncryptModeXChaCha20,
	}
}

// SecretType тип секрета
type SecretType uint8

const (
	SecretTypeText SecretType = iota + 1
	SecretTypeFile
)

func (st SecretType) String() string {
	switch st {
	case SecretTypeText:
		return "text"
	case SecretTypeFile:
		return "file"
	default:
		return "unknown"
	}
}

// EncryptMode режим шифрования
type EncryptMode uint8

const (
	EncryptModeChaCha20 EncryptMode = iota + 1
	EncryptModeXChaCha20
)

func (em EncryptMode) String() string {
	switch em {
	case EncryptModeChaCha20:
		return "chacha20poly1305"
	case EncryptModeXChaCha20:
		return "xchacha20poly1305"
	default:
		return "unknown"
	}
}

// NonceSize возвращает размер nonce для режима шифрования
func NonceSize(mode EncryptMode) int {
	switch mode {
	case EncryptModeChaCha20:
		return 12
	case EncryptModeXChaCha20:
		return 24
	default:
		return 12
	}
}

// Флаги состояния
const (
	FlagUndefined uint8 = 0 // undefined flag set in the start of writing
	FlagCompleted uint8 = 1 << (iota - 1)
	FlagEncrypted
	FlagCompressed
	FlagDeleted
)

// ContainerInfo информация о контейнере
type ContainerInfo struct {
	Version     uint8
	SecretCount uint32
	DataSize    uint64
	CreatedAt   int64
	ModifiedAt  int64
}

func CurrentUnixTime() uint64 {
	return uint64(time.Now().Unix())
}
