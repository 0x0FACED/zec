package types

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/0x0FACED/zec/pkg/core/v1/crypto"
)

type IndexTable struct {
	Secrets []SecretMeta // slice of secrets metadata
}

func (it *IndexTable) Encrypt(fek []byte, nonce []byte) ([]byte, error) {
	// serialize secrets meta to bytes
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(it.Secrets); err != nil {
		return nil, err
	}

	ciphertext, err := crypto.EncryptChaCha20Poly1305(fek, nonce, buf.Bytes())
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func (it *IndexTable) Decrypt(fek []byte, nonce []byte, ciphertext []byte) error {
	plaintext, err := crypto.DecryptChaCha20Poly1305(fek, nonce, ciphertext)
	if err != nil {
		return err
	}

	// deserialize bytes to secrets meta
	var secrets []SecretMeta
	if err := gob.NewDecoder(bytes.NewReader(plaintext)).Decode(&secrets); err != nil {
		return err
	}

	it.Secrets = secrets

	return nil
}

func DecryptIndexTableFromCipher(fek []byte, nonce []byte, ciphertext []byte) (*IndexTable, error) {
	plaintext, err := crypto.DecryptChaCha20Poly1305(fek, nonce, ciphertext)
	if err != nil {
		return nil, err
	}

	var table IndexTable
	var secrets []SecretMeta
	if err := gob.NewDecoder(bytes.NewReader(plaintext)).Decode(&secrets); err != nil {
		return nil, fmt.Errorf("failed to decode index table: %w", err)
	}

	table.Secrets = secrets

	return &table, nil
}
