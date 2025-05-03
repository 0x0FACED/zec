package types

import (
	"encoding/binary"
	"io"
)

type IndexTable struct {
	Secrets []SecretMeta // slice of secrets metadata
}

// TEST METHOD
func (t *IndexTable) Encode(w io.Writer) error {
	count := uint32(len(t.Secrets))
	if err := binary.Write(w, binary.LittleEndian, count); err != nil {
		return err
	}

	for _, secret := range t.Secrets {
		if err := binary.Write(w, binary.LittleEndian, secret); err != nil {
			return err
		}
	}
	return nil
}

// TEST METHOD
func (t *IndexTable) Decode(r io.Reader) error {
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return err
	}

	t.Secrets = make([]SecretMeta, count)
	for i := uint32(0); i < count; i++ {
		if err := binary.Read(r, binary.LittleEndian, &t.Secrets[i]); err != nil {
			return err
		}
	}
	return nil
}
