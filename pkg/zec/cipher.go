package zec

import "io"

type Cipher interface {
	Encrypt(key, nonce []byte, src io.Reader, dst io.Writer, mode EncryptMode) (uint64, error)
	Decrypt(key, nonce []byte, src io.Reader, mode EncryptMode) (io.ReadCloser, error)
}

// ChaCha20Cipher реализация Cipher для ChaCha20 и XChaCha20
type ChaCha20Cipher struct{}

func NewChaCha20Cipher() Cipher {
	return &ChaCha20Cipher{}
}

func (c *ChaCha20Cipher) Encrypt(key, nonce []byte, src io.Reader, dst io.Writer, mode EncryptMode) (uint64, error) {
	switch mode {
	case EncryptModeChaCha20:
		return encryptChaCha20Poly1305(key, nonce, src, dst)
	case EncryptModeXChaCha20:
		return encryptXChaCha20Poly1305(key, nonce, src, dst)
	default:
		return 0, ErrUnsupportedEncryptMode
	}
}

func (c *ChaCha20Cipher) Decrypt(key, nonce []byte, src io.Reader, mode EncryptMode) (io.ReadCloser, error) {
	switch mode {
	case EncryptModeChaCha20:
		return decryptChaCha20Poly1305(key, nonce, src)
	case EncryptModeXChaCha20:
		return decryptXChaCha20Poly1305(key, nonce, src)
	default:
		return nil, ErrUnsupportedEncryptMode
	}
}

