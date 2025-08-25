package zec

import "errors"

// TODO: Обновить ошибки, а то чет не нравится мне
var (
	// Ошибки контейнера
	ErrContainerNotFound  = errors.New("container not found")
	ErrContainerCorrupted = errors.New("container is corrupted")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrNoActiveSession    = errors.New("no active session")

	// Ошибки секретов
	ErrSecretExists   = errors.New("secret already exists")
	ErrSecretNotFound = errors.New("secret not found")
	ErrSecretDeleted  = errors.New("secret is deleted")
	ErrSecretTooLarge = errors.New("secret is too large")

	// Ошибки шифрования
	ErrUnsupportedEncryptMode = errors.New("unsupported encryption mode")
	ErrDecryptionFailed       = errors.New("decryption failed")
	ErrInvalidNonce           = errors.New("invalid nonce size")

	// Ошибки целостности
	ErrChecksumMismatch = errors.New("checksum mismatch")
	ErrInvalidHeader    = errors.New("invalid header")
	ErrInvalidIndex     = errors.New("invalid index table")

	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionInactive = errors.New("session is inactive")
)
