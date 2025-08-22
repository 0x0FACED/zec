package crypto

import (
	"crypto/hmac"
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

type KeyManagerIface interface {
	MasterKey32() []byte
	Close()
}

type FEKManager struct {
	km KeyManagerIface
}

func NewFEKManager(keyManager KeyManagerIface) *FEKManager {
	return &FEKManager{
		km: keyManager,
	}
}

// EncryptRandom generates 32 byte slice and encrypts in using KeyManager.
func (f *FEKManager) EncryptRandom() (encryptedFEK [60]byte, err error) {
	// generate random FEK (32 bytes)
	var fek [32]byte
	if _, err = rand.Read(fek[:]); err != nil {
		return
	}

	key := f.km.MasterKey32()
	// encrypt FEK with master key (ChaCha20-Poly1305)
	aead, err := chacha20poly1305.New(key)
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

// Encrypt encrypts given randomFEK using key fom key manager and provided nonce.
func (f *FEKManager) Encrypt(randomFEK [32]byte, nonce [12]byte) (encryptedFEK [60]byte, err error) {
	key := f.km.MasterKey32()
	// encrypt FEK with master key (ChaCha20-Poly1305)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return encryptedFEK, err
	}

	ciphertext := aead.Seal(nil, nonce[:], randomFEK[:], nil)

	// fill encryptedFEK (12 nonce + 32 ciphertext + 16 auth tag)
	copy(encryptedFEK[0:12], nonce[:])
	copy(encryptedFEK[12:], ciphertext)

	return encryptedFEK, nil
}

func (f *FEKManager) Decrypt(encryptedFEK [60]byte, verificationTag [16]byte, headerBytes []byte) (fek [32]byte, err error) {
	masterKey := f.km.MasterKey32()
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
