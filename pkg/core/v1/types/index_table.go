package types

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"slices"

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

func (it *IndexTable) SecretByName(name [32]byte) (*SecretMeta, error) {
	for i := range it.Secrets {
		if it.Secrets[i].Name == name {
			return &it.Secrets[i], nil
		}
	}

	return nil, errors.New("secret not found")
}

func (it *IndexTable) NextSecretIdx(name [32]byte) (int, error) {
	for i := range it.Secrets {
		if it.Secrets[i].Name == name {
			if i < len(it.Secrets) {
				return i + 1, nil
			}

			return -1, errors.New("no next secrets")
		}
	}

	return -1, errors.New("secret not found")
}

func (it *IndexTable) RemoveByName(name [32]byte) error {
	for i, s := range it.Secrets {
		if s.Name == name {
			if i < len(it.Secrets) {
				it.Secrets = slices.Delete(it.Secrets, i, i+1)
				return nil
			}

			return errors.New("no next secrets")
		}
	}

	return errors.New("secret not found")
}

// test func
func (it *IndexTable) Print() {
	for i, v := range it.Secrets {
		fmt.Printf("Secret #%d, name %s, offset %d, size %d\n", i, v.Name, v.Offset, v.Size)
	}
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
