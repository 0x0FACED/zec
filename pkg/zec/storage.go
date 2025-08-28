package zec

import "io"

// Storage это жирная асбтракция над всем хранилищем (так и задумано,
// это не говнокод, ну или все же говнокод)
type Storage interface {
	// Инициализация нового хранилища
	Initialize(header Header) error

	// Операции с заголовком
	GetHeader() (Header, error)
	UpdateHeader(header Header) error
	SetSession(session *Session)

	// Операции с секретами
	SecretExists(name string) (bool, error)
	GetSecretMeta(name string) (SecretMeta, error)
	AddSecretMeta(meta SecretMeta) error
	ListSecrets() []SecretMeta
	DeleteSecretSoft(name string) error
	DeleteSecretHard(name string) error

	// Операции с данными
	GetDataReader(offset, size uint64) (io.ReadCloser, error)
	GetDataWriter() (io.WriteCloser, uint64, error) // writer, offset

	// Управление состоянием
	Save() error
	Close() error
	ValidateChecksum() error
}
