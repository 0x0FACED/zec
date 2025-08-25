package zec

import (
	"context"
	"io"
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

// DefaultContainerOptions возрвщает дефолтные опции
func DefaultContainerOptions() ContainerOptions {
	return ContainerOptions{
		ArgonMemory:      1 << 18, // 256KB
		ArgonIterations:  5,
		ArgonParallelism: 1,
		BlockSize:        4 * 1024 * 1024, // 4MB
	}
}

func NewContainer(storage Storage, password []byte, opts ContainerOptions) (*Container, error) {
	cipher := NewChaCha20Cipher()

	header, err := NewHeader(opts)
	if err != nil {
		return nil, err
	}

	if err := storage.Initialize(*header); err != nil {
		return nil, err
	}

	// дерайвим МК
	masterKey := DeriveKey(password, header.ArgonSalt, header.ArgonMemoryLog2,
		header.ArgonIterations, header.ArgonParallelism)

	fek, encryptedFEK, err := GenerateAndEncryptFEK(masterKey)
	if err != nil {
		return nil, err
	}

	header.EncryptedFEK = encryptedFEK
	header.VerificationTag = CalculateHMAC(masterKey, header.AuthenticatedBytes())

	if err := storage.UpdateHeader(*header); err != nil {
		return nil, err
	}

	// TODO: айди как-то надо определять иначе
	session := NewSession("new-container", masterKey, fek)

	return &Container{
		storage: storage,
		cipher:  cipher,
		session: session,
	}, nil
}

func OpenContainer(storage Storage, password []byte) (*Container, error) {
	cipher := NewChaCha20Cipher()

	header, err := storage.GetHeader()
	if err != nil {
		return nil, err
	}

	masterKey := DeriveKey(password, header.ArgonSalt, header.ArgonMemoryLog2,
		header.ArgonIterations, header.ArgonParallelism)

	fek, err := DecryptFEK(masterKey, header.EncryptedFEK,
		header.VerificationTag, header.AuthenticatedBytes())
	if err != nil {
		return nil, err
	}

	// TODO: аналогично New
	session := NewSession("opened-container", masterKey, fek)

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

	meta := &SecretMeta{
		Name:        name,
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

func (c *Container) ListSecrets() ([]SecretInfo, error) {
	metas, err := c.storage.ListSecrets()
	if err != nil {
		return nil, err
	}

	var secrets []SecretInfo
	for _, meta := range metas {
		if meta.Flags&FlagDeleted == 0 { // только не удаленные
			secrets = append(secrets, SecretInfo{
				Name:       meta.Name,
				Type:       meta.Type,
				Size:       meta.Size,
				CreatedAt:  meta.CreatedAt,
				ModifiedAt: meta.ModifiedAt,
			})
		}
	}

	return secrets, nil
}

// DeleteSecret удаляет секрет (мягко или принудительно)
func (c *Container) DeleteSecret(name string, force bool) error {
	if force {
		return c.storage.DeleteSecretHard(name)
	}
	return c.storage.DeleteSecretSoft(name)
}
func (c *Container) Info() (*ContainerInfo, error) {
	header, err := c.storage.GetHeader()
	if err != nil {
		return nil, err
	}

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

func (c *Container) IsSessionActive() bool {
	return c.session != nil && c.session.IsActive()
}

func (c *Container) RefreshSession() {
	if c.session != nil {
		c.session.Touch()
	}
}

func (c *Container) Close() error {
	if err := c.storage.Save(); err != nil {
		return err
	}

	if c.session != nil {
		if err := c.session.Close(); err != nil {
			return err
		}
	}

	return c.storage.Close()
}
