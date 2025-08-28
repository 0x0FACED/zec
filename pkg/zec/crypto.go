package zec

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// DeriveKey создает мастер-ключ из пароля используя Argon2
func DeriveKey(password []byte, salt [16]byte, memoryLog2 uint8, iterations uint16, parallelism uint8) [32]byte {
	memory := uint32(1) << memoryLog2
	key := argon2.IDKey(password, salt[:], uint32(iterations), memory, uint8(parallelism), 32)

	var result [32]byte
	copy(result[:], key)
	return result
}

func GenerateAndEncryptFEK(masterKey [32]byte) ([60]byte, error) {
	var fek [32]byte
	if _, err := rand.Read(fek[:]); err != nil {
		return [60]byte{}, err
	}

	aead, err := chacha20poly1305.New(masterKey[:])
	if err != nil {
		return [60]byte{}, err
	}

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [60]byte{}, err
	}

	ciphertext := aead.Seal(nil, nonce[:], fek[:], nil)

	// nonce(12) + ciphertext(32) + tag(16)
	var encryptedFEK [60]byte
	copy(encryptedFEK[0:12], nonce[:])
	copy(encryptedFEK[12:], ciphertext)

	return encryptedFEK, nil
}

func EncryptFEK(fek, masterKey [32]byte) ([60]byte, error) {
	aead, err := chacha20poly1305.New(masterKey[:])
	if err != nil {
		return [60]byte{}, err
	}

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [60]byte{}, err
	}

	ciphertext := aead.Seal(nil, nonce[:], fek[:], nil)

	// nonce(12) + ciphertext(32) + tag(16)
	var encryptedFEK [60]byte
	copy(encryptedFEK[0:12], nonce[:])
	copy(encryptedFEK[12:], ciphertext)

	return encryptedFEK, nil
}

func DecryptFEK(masterKey [32]byte, encryptedFEK [60]byte, verificationTag [16]byte, headerBytes []byte) ([32]byte, error) {
	expectedTag := CalculateHMAC(masterKey, headerBytes)
	if !hmac.Equal(expectedTag[:16], verificationTag[:]) {
		return [32]byte{}, ErrInvalidPassword
	}

	aead, err := chacha20poly1305.New(masterKey[:])
	if err != nil {
		return [32]byte{}, err
	}

	nonce := encryptedFEK[0:12]
	ciphertext := encryptedFEK[12:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return [32]byte{}, ErrInvalidPassword
	}

	var fek [32]byte
	copy(fek[:], plaintext)
	return fek, nil
}

func CalculateHMAC(masterKey [32]byte, data []byte) [16]byte {
	h := hmac.New(sha256.New, masterKey[:])
	h.Write([]byte("zec-verification"))
	h.Write(data)

	var result [16]byte
	copy(result[:16], h.Sum(nil))
	return result
}

func GenerateNonce(mode EncryptMode) ([]byte, error) {
	size := NonceSize(mode)
	nonce := make([]byte, size)

	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

func GenerateNonce12() ([12]byte, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [12]byte{}, err
	}
	return nonce, nil
}

func GenerateSalt16() ([16]byte, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return [16]byte{}, err
	}
	return salt, nil
}

func encryptChaCha20Poly1305(key, nonce []byte, src io.Reader, dst io.Writer) (uint64, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, err
	}

	data, err := io.ReadAll(src)
	if err != nil {
		return 0, err
	}

	encrypted := aead.Seal(nil, nonce, data, nil)

	n, err := dst.Write(encrypted)
	return uint64(n), err
}

// encryptXChaCha20Poly1305 шифрует потоково
func encryptXChaCha20Poly1305(key, nonce []byte, src io.Reader, dst io.Writer) (uint64, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, err
	}

	const blockSize = 128 * 1024 // 128KB блоки (совместимость со старой версией)
	buf := make([]byte, blockSize)
	var totalWritten uint64
	var blockNum uint64

	for {
		n, err := src.Read(buf)
		if n > 0 {
			blockNonce := deriveBlockNonce(nonce, blockNum)

			encrypted := aead.Seal(nil, blockNonce, buf[:n], nil)

			written, werr := dst.Write(encrypted)
			if werr != nil {
				return totalWritten, werr
			}

			totalWritten += uint64(written)
			blockNum++
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return totalWritten, err
		}
	}

	return totalWritten, nil
}

func decryptChaCha20Poly1305(key, nonce []byte, src io.Reader) (io.ReadCloser, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	encrypted, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	decrypted, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(decrypted)), nil
}

func decryptXChaCha20Poly1305(key, nonce []byte, src io.Reader) (io.ReadCloser, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &streamDecryptor{
		aead:      aead,
		src:       src,
		baseNonce: nonce,
		blockSize: 128*1024 + aead.Overhead(), // размер блока + overhead (совместимость)
	}, nil
}

// deriveBlockNonce создает nonce для конкретного блока
func deriveBlockNonce(baseNonce []byte, blockNum uint64) []byte {
	nonce := make([]byte, 24)   // XChaCha20 использует 24-байтовый nonce
	copy(nonce, baseNonce[:16]) // Копируем первые 16 байт базового nonce

	// Записываем номер блока в последние 8 байт используя little-endian
	for i := 0; i < 8; i++ {
		nonce[16+i] = byte(blockNum >> (i * 8))
	}

	return nonce
}

type streamDecryptor struct {
	aead      cipher.AEAD
	src       io.Reader
	baseNonce []byte
	blockSize int
	blockNum  uint64
	buf       []byte
	remaining []byte
}

func (sd *streamDecryptor) Read(p []byte) (n int, err error) {
	if len(sd.remaining) > 0 {
		n = copy(p, sd.remaining)
		sd.remaining = sd.remaining[n:]
		return n, nil
	}

	if sd.buf == nil {
		sd.buf = make([]byte, sd.blockSize)
	}

	blockBytes, err := sd.src.Read(sd.buf)
	if blockBytes == 0 {
		return 0, err
	}

	blockNonce := deriveBlockNonce(sd.baseNonce, sd.blockNum)
	decrypted, derr := sd.aead.Open(nil, blockNonce, sd.buf[:blockBytes], nil)
	if derr != nil {
		return 0, derr
	}

	sd.blockNum++

	n = copy(p, decrypted)
	if n < len(decrypted) {
		sd.remaining = decrypted[n:]
	}

	return n, nil
}

func (sd *streamDecryptor) Close() error {
	if closer, ok := sd.src.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
