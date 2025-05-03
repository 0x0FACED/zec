package file

import (
	"fmt"
	"io"
	"os"

	"github.com/0x0FACED/zec/pkg/core/v1/types"
)

// TEST FUNC
func ReadAllSecretsFromIndex(f *os.File, index types.IndexTable) ([]types.SecretData, error) {
	var secrets []types.SecretData

	for _, meta := range index.Secrets {
		// check if the secret marked is deleted
		if meta.Flags&types.FlagDeleted != 0 {
			// marked as deleted - continue
			continue
		}

		// prepare buffer for secret
		buf := make([]byte, meta.Size)

		// read secret and write to buf
		_, err := f.ReadAt(buf, int64(meta.Offset))
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("unexpected EOF at offset %d", meta.Offset)
			}
			return nil, fmt.Errorf("failed to read secret at offset %d: %w", meta.Offset, err)
		}

		// add to slice
		secrets = append(secrets, types.SecretData{
			Meta: meta,
			Val:  buf,
		})
	}

	return secrets, nil
}
