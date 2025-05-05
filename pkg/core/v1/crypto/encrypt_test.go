package crypto_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/0x0FACED/zec/pkg/core/v1/crypto"
	"github.com/stretchr/testify/assert"
)

func TestEncrypt_EncAndDec_Success(t *testing.T) {
	// encrypt
	key := "test"
	hash := sha256.New()
	_, err := hash.Write([]byte(key))
	assert.NoError(t, err)

	hashKey := hash.Sum(nil)

	// rand nonce of 12 bytes len
	var nonce [12]byte
	_, err = rand.Read(nonce[:])
	assert.NoError(t, err)

	secret := "secret-data"
	cipher, err := crypto.EncryptChaCha20Poly1305(hashKey, nonce[:], []byte(secret))
	assert.NoError(t, err)

	// decrypt

	plaintext, err := crypto.DecryptChaCha20Poly1305(hashKey, nonce[:], cipher)
	assert.NoError(t, err)

	assert.Equal(t, secret, string(plaintext))
}

func TestEncrypt_Enc_InvalidNonceSize(t *testing.T) {
	// encrypt
	key := "test"
	hash := sha256.New()
	_, err := hash.Write([]byte(key))
	assert.NoError(t, err)

	hashKey := hash.Sum(nil)

	// rand nonce of 24 bytes len
	// New() required 12 len byte nonce
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	assert.NoError(t, err)

	secret := "secret-data"
	_, err = crypto.EncryptChaCha20Poly1305(hashKey, nonce[:], []byte(secret))
	assert.Error(t, err)
	assert.Equal(t, crypto.ErrInvalidNonceSize, err)
}
