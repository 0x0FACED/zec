package zec

import "time"

// SecretMeta метаданные секрета
type SecretMeta struct {
	Name        string
	Offset      uint64
	Size        uint64
	CreatedAt   int64
	ModifiedAt  int64
	Type        SecretType
	Flags       uint8
	Nonce       [24]byte // максимальный размер для XChaCha20
	EncryptMode EncryptMode
}

// SecretInfo публичная информация о секрете
type SecretInfo struct {
	Name       string
	Type       SecretType
	Size       uint64
	CreatedAt  int64
	ModifiedAt int64
}

// SecretOptions опции для операций с секретами
type SecretOptions struct {
	Type        SecretType
	EncryptMode EncryptMode
}

func DefaultSecretOptions() *SecretOptions {
	return &SecretOptions{
		Type:        SecretTypeText,
		EncryptMode: EncryptModeChaCha20,
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
	FlagUndefined       = 0 // undefined flag set in the start of writing
	FlagCompleted uint8 = 1 << iota
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

// Session данные активной сессии
// Вообще канеш тоже такое себе, агенту не хватит этого, нужен будет менеджер сессий
// К тому же хранить надо и fek, и МК в анклаве
type Session struct {
	masterKey [32]byte
	fek       [32]byte
}

func CurrentUnixTime() int64 {
	return time.Now().Unix()
}
