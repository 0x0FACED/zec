package zec

import (
	"context"
	"fmt"
	"io"

	"github.com/0x0FACED/uuid"
	"github.com/0x0FACED/zec/pkg/zec/helpers"
)

// Container представляет зашифрованный контейнер ZEC
type Container struct {
	storage Storage
	cipher  Cipher
	session *Session
}

// ContainerOptions опции для создания/открытия контейнера
type ContainerOptions struct {
	ArgonMemory      uint32
	ArgonIterations  uint16
	ArgonParallelism uint8
	BlockSize        int64
}

// DefaultContainerOptions возвращает дефолтные опции
func DefaultContainerOptions() ContainerOptions {
	return ContainerOptions{
		ArgonMemory:      1 << 18, // 256KB
		ArgonIterations:  5,
		ArgonParallelism: 1,
		BlockSize:        4 * 1024 * 1024, // 4MB
	}
}

// ContainerManager - высокоуровневая абстракция для управления контейнерами
type ContainerManager struct {
	options ContainerOptions
}

// NewContainerManager создает новый менеджер контейнеров
func NewContainerManager(opts ContainerOptions) *ContainerManager {
	return &ContainerManager{options: opts}
}

// CreateNew создает новый контейнер с файлом
func (cm *ContainerManager) CreateNew(path, password string) (*Container, error) {
	storage, err := NewFileStorage(path, cm.options)
	if err != nil {
		return nil, err
	}

	header, err := NewHeader(cm.options)
	if err != nil {
		return nil, err
	}

	if err := storage.Initialize(*header); err != nil {
		return nil, err
	}

	containerID := uuid.NewV4().String()
	session, err := NewSessionForNewContainer(containerID, []byte(password), *header)
	if err != nil {
		return nil, err
	}

	// он уже выставляется при создании сессии
	// опять же ужасный код, плохие решения
	header.EncryptedFEK = session.EncryptedFEK()
	header.VerificationTag = CalculateHMAC(session.MasterKey(), header.AuthenticatedBytes())

	if err := storage.UpdateHeader(*header); err != nil {
		return nil, err
	}

	session.SetHeader(*header)
	storage.SetSession(session)

	return &Container{
		storage: storage,
		cipher:  NewChaCha20Cipher(),
		session: session,
	}, nil
}

// OpenExisting открывает существующий контейнер
func (cm *ContainerManager) OpenExisting(path, password string) (*Container, error) {
	storage, err := OpenFileStorage(path)
	if err != nil {
		return nil, err
	}

	header := storage.GetHeader()

	containerID := uuid.NewV4().String()
	session, err := NewSession(containerID, []byte(password), header)
	if err != nil {
		return nil, err
	}

	storage.SetSession(session)
	if err := storage.LoadIndex(); err != nil {
		return nil, err
	}

	return &Container{
		storage: storage,
		cipher:  NewChaCha20Cipher(),
		session: session,
	}, nil
}

func NewContainer(storage Storage, session *Session, opts ContainerOptions) (*Container, error) {
	cipher := NewChaCha20Cipher()

	header, err := NewHeader(opts)
	if err != nil {
		return nil, err
	}

	if err := storage.Initialize(*header); err != nil {
		return nil, err
	}

	header.EncryptedFEK = session.EncryptedFEK()
	header.VerificationTag = CalculateHMAC(session.MasterKey(), header.AuthenticatedBytes())

	if err := storage.UpdateHeader(*header); err != nil {
		return nil, err
	}

	return &Container{
		storage: storage,
		cipher:  cipher,
		session: session,
	}, nil
}

func OpenContainer(storage Storage, session *Session) (*Container, error) {
	cipher := NewChaCha20Cipher()

	return &Container{
		storage: storage,
		cipher:  cipher,
		session: session,
	}, nil
}

func (c *Container) AddSecret(ctx context.Context, name string, data io.Reader, opts *SecretOptions) error {
	if opts == nil {
		opts = DefaultSecretOptions()
	}

	if !c.session.IsActive() {
		return ErrSessionExpired
	}

	if exists, err := c.storage.SecretExists(name); err != nil {
		return err
	} else if exists {
		return ErrSecretExists
	}

	nameBytes, err := helpers.ConvertStringNameToBytes32(name)
	if err != nil {
		return err
	}
	meta := &SecretMeta{
		Name:        nameBytes,
		Type:        opts.Type,
		EncryptMode: opts.EncryptMode,
		CreatedAt:   CurrentUnixTime(),
		ModifiedAt:  CurrentUnixTime(),
	}

	writer, offset, err := c.storage.GetDataWriter()
	if err != nil {
		return err
	}
	defer writer.Close()

	meta.Offset = offset

	nonce, err := GenerateNonce(opts.EncryptMode)
	if err != nil {
		return err
	}
	copy(meta.Nonce[:], nonce)

	fek := c.session.FEK()
	size, err := c.cipher.Encrypt(fek[:], nonce, data, writer, opts.EncryptMode)
	if err != nil {
		return err
	}

	meta.Size = size
	meta.Flags = FlagCompleted | FlagEncrypted

	return c.storage.AddSecretMeta(*meta)
}

func (c *Container) GetSecret(ctx context.Context, name string) (io.ReadCloser, error) {
	if !c.session.IsActive() {
		return nil, ErrSessionExpired
	}

	meta, err := c.storage.GetSecretMeta(name)
	if err != nil {
		return nil, err
	}

	if meta.Flags&FlagDeleted != 0 {
		return nil, ErrSecretDeleted
	}

	reader, err := c.storage.GetDataReader(meta.Offset, meta.Size)
	if err != nil {
		return nil, err
	}

	nonce := meta.Nonce[:NonceSize(meta.EncryptMode)]
	fek := c.session.FEK()
	return c.cipher.Decrypt(fek[:], nonce, reader, meta.EncryptMode)
}

func (c *Container) ListSecrets() []SecretMeta {
	return c.storage.ListSecrets()
}

// DeleteSecret удаляет секрет (мягко или принудительно)
func (c *Container) DeleteSecret(name string, force bool) error {
	if force {
		return c.storage.DeleteSecretHard(name)
	}
	return c.storage.DeleteSecretSoft(name)
}
func (c *Container) Info() (*ContainerInfo, error) {
	header := c.storage.GetHeader()

	return &ContainerInfo{
		Version:     header.Version,
		SecretCount: header.SecretCount,
		DataSize:    header.DataSize,
		CreatedAt:   header.CreatedAt,
		ModifiedAt:  header.ModifiedAt,
	}, nil
}

func (c *Container) ValidateIntegrity() error {
	return c.storage.ValidateChecksum()
}

func (c *Container) Session() *Session {
	return c.session
}

func (c *Container) Header() Header {
	return c.storage.GetHeader()
}

func (c *Container) IsSessionActive() bool {
	return c.session != nil && c.session.IsActive()
}

func (c *Container) RefreshSession() {
	if c.session != nil {
		c.session.Touch()
	}
}

func (c *Container) Close() error {
	if c.session != nil {
		if c.storage == nil {
			return fmt.Errorf("warning: storage is nil while closing container")
		}
		if err := c.storage.Close(); err != nil {
			return err
		}
	}

	return nil
}
