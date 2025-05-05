package crypto

import (
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidNonceSize = errors.New("zec/crypto: invalid nonce size")
)

const ChaCha20NonceSize = chacha20poly1305.NonceSize
const ChaCha20NonceSizeX = chacha20poly1305.NonceSizeX

func EncryptChaCha20Poly1305(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(nonce) != ChaCha20NonceSize {
		return nil, ErrInvalidNonceSize
	}
	// 32 byte key
	// New returns aead with required 12 byte nonce
	// NewX expects 24 byte nonce
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	encrypted := aead.Seal(nil, nonce, plaintext, nil)

	return encrypted, nil
}

func DecryptChaCha20Poly1305(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(nonce) != ChaCha20NonceSize {
		return nil, ErrInvalidNonceSize
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
