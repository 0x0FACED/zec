package types

import (
	"fmt"
	"os"
)

type SecretData struct {
	Meta SecretMeta // not written as secret
	Val  []byte     // secret data (must be excrypted + zipped, but not now)
}

func (sd *SecretData) WriteToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	n, err := f.Write(sd.Val)
	if err != nil {
		return err
	}

	if n != len(sd.Val) {
		return fmt.Errorf("zec/types/secret_data.go: written file size is not equal to secret size")
	}

	return nil
}
