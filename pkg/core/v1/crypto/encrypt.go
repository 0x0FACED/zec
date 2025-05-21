package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidNonceSize = errors.New("zec/crypto: invalid nonce size")
	ErrInvalidBlock     = errors.New("zec/crypto: invalid block during decryption")
	ErrCreateAEAD       = errors.New("zec/crypto: failed to chacha20poly1305.New() with 256-bit key")
	ErrCreateAEADX      = errors.New("zec/crypto: failed to chacha20poly1305.NewX() with 256-bit key")
	ErrAEADOpen         = errors.New("zec/crypto: failed to aead.Open() with provided nonce and ciphertext")
	ErrWrite            = errors.New("zec/crypto: failed to Write()")
	ErrRead             = errors.New("zec/crypto: failed to Read()")
	ErrTruncatedBlock   = errors.New("zec/crypto: truncated block")
)

const ChaCha20NonceSize = chacha20poly1305.NonceSize
const ChaCha20NonceSizeX = chacha20poly1305.NonceSizeX
const BlockSize = 128 * 1024 // 128 kb

func EncryptChaCha20Poly1305(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(nonce) != ChaCha20NonceSize {
		return nil, ErrInvalidNonceSize
	}
	// 32 byte key
	// New returns aead with required 12 byte nonce
	// NewX expects 24 byte nonce
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCreateAEAD, err)
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
		return nil, fmt.Errorf("%w: %w", ErrCreateAEAD, err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAEADOpen, err)
	}

	return plaintext, nil
}

func EncryptXChaCha20Poly1305(key, baseNonce []byte, plaintext io.Reader, ciphertext io.Writer) error {
	if len(baseNonce) != ChaCha20NonceSizeX {
		return ErrInvalidNonceSize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCreateAEADX, err)
	}

	var blockIndex uint64

	buf := make([]byte, BlockSize)
	for {
		n, err := plaintext.Read(buf)
		if n > 0 {
			blockNonce := deriveBlockNonce(baseNonce, blockIndex)
			block := buf[:n]
			enc := aead.Seal(nil, blockNonce, block, nil)
			if _, err := ciphertext.Write(enc); err != nil {
				return fmt.Errorf("%w: %w", ErrWrite, err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrRead, err)
		}

		blockIndex++
	}

	return nil
}

func DecryptXChaCha20Poly1305(key, baseNonce []byte, ciphertext io.Reader, plaintext io.Writer) error {
	if len(baseNonce) != ChaCha20NonceSizeX {
		return ErrInvalidNonceSize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCreateAEADX, err)
	}

	var blockIndex uint64
	buf := make([]byte, BlockSize+aead.Overhead()) // ciphertext block = block + aead tag

	for {
		n, err := ciphertext.Read(buf)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			return fmt.Errorf("%w: %w", ErrTruncatedBlock, err)
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrRead, err)
		}

		blockNonce := deriveBlockNonce(baseNonce, blockIndex)
		block := buf[:n]
		dec, err := aead.Open(nil, blockNonce, block, nil)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrAEADOpen, err)
		}

		if _, err := plaintext.Write(dec); err != nil {
			return fmt.Errorf("%w: %w", ErrWrite, err)
		}

		blockIndex++
	}

	return nil
}

func deriveBlockNonce(baseNonce []byte, blockIndex uint64) []byte {
	nonce := make([]byte, ChaCha20NonceSizeX)
	copy(nonce, baseNonce[:16])
	binary.LittleEndian.PutUint64(nonce[16:], blockIndex)
	return nonce
}
