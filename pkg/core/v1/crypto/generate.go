package crypto

import (
	"crypto/rand"
	"fmt"
)

func Nonce12() ([12]byte, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [12]byte{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return nonce, nil
}

func Nonce24() ([24]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [24]byte{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return nonce, nil
}

func Salt16() ([16]byte, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return [16]byte{}, fmt.Errorf("failed to generate sal16: %w", err)
	}

	return salt, nil
}

func Salt32() ([32]byte, error) {
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return [32]byte{}, fmt.Errorf("failed to generate sal32: %w", err)
	}

	return salt, nil
}
