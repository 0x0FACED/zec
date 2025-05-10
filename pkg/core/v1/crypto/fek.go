package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// ==========================
// CONSTANTS AND TYPES
// ==========================

const (
	FekKeySize          = 32 // FEK = 32 bytes
	EncryptedFEKSize    = 60 // nonce (12) + ciphertext (32) + tag (16)
	VerificationTagSize = 16
)

var (
	ErrInvalidPassword  = errors.New("zec/crypto: invalid password or corrupted verification tag")
	ErrDecryptionFailed = errors.New("zec/crypto: decryption failed (possibly corrupted EncryptedFEK or wrong password)")
)

const (
	ZecVerification = "zec-verification"
)

// ==========================
// PUBLIC FUNCTIONS
// ==========================

// Argon2idMasterKey32 returns 256 bit master key generated from password
// with provided argon2 parameters.
func Argon2idMasterKey32(password []byte, salt [16]byte, memoryLog2 uint8, iterations uint16, parallelism uint8) []byte {
	memory := 1 << memoryLog2
	masterKey := argon2.IDKey(password, salt[:], uint32(iterations), uint32(memory), uint8(parallelism), 32)
	return masterKey
}

// EncryptFEK encrypts a randomly generated FEK with a derived master key.
func EncryptFEK(masterKey []byte) (encryptedFEK [60]byte, err error) {
	// generate random FEK (32 bytes)
	var fek [32]byte
	if _, err = rand.Read(fek[:]); err != nil {
		return
	}

	// encrypt FEK with master key (ChaCha20-Poly1305)
	aead, err := chacha20poly1305.New(masterKey)
	if err != nil {
		return
	}

	var nonce [12]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return
	}

	ciphertext := aead.Seal(nil, nonce[:], fek[:], nil)

	// fill encryptedFEK (12 nonce + 32 ciphertext + 16 auth tag)
	copy(encryptedFEK[0:12], nonce[:])
	copy(encryptedFEK[12:], ciphertext)

	return encryptedFEK, nil
}

// DecryptFEK recovers the FEK using the master key and
func DecryptFEK(masterKey []byte, encryptedFEK [60]byte, verificationTag [16]byte, headerBytes []byte) (fek [32]byte, err error) {
	expectedTag := HMAC([32]byte(masterKey), headerBytes)

	if !hmac.Equal(expectedTag[:VerificationTagSize], verificationTag[:]) {
		err = ErrInvalidPassword
		return
	}

	// decrypt FEK
	aead, err := chacha20poly1305.New(masterKey)
	if err != nil {
		return
	}

	nonce := encryptedFEK[0:12]
	ciphertext := encryptedFEK[12:]

	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil || len(plain) != 32 {
		err = ErrDecryptionFailed
		return
	}

	copy(fek[:], plain)
	return
}
