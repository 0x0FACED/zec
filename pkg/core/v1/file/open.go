package file

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/0x0FACED/zec/pkg/core/v1/crypto"
	"github.com/0x0FACED/zec/pkg/core/v1/types"
)

func Open(path string, password []byte) (*types.SecretFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	// Read the header
	header := types.Header{}
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	masterKey := crypto.Argon2idMasterKey32(password, header.ArgonSalt, header.ArgonMemoryLog2, header.ArgonIterations, header.ArgonParallelism)

	// verify pass
	fek, err := crypto.DecryptFEK(masterKey, header.EncryptedFEK, header.VerificationTag)
	if err != nil {
		return nil, err
	}

	// get index table offset
	indexTableOffset := header.IndexTableOffset

	// set seek to the index table offset
	_, err = f.Seek(int64(indexTableOffset), io.SeekStart)
	if err != nil {
		return nil, err
	}

	// Read the index table
	indexTable, err := ReadIndexTable(fek, f, &header)
	if err != nil {
		return nil, err
	}

	// we dont read secrets. we only read header and index table
	// so its secured
	// Create the SecretFile struct
	secretFile := &types.SecretFile{}

	secretFile.SetFile(f)
	secretFile.SetMasterKey(masterKey)
	secretFile.SetHeader(header)
	secretFile.SetIndexTable(*indexTable)

	return secretFile, nil
}

func ReadIndexTable(fek [32]byte, f *os.File, header *types.Header) (*types.IndexTable, error) {
	// set read to IndexTableOffset
	_, err := f.Seek(int64(header.IndexTableOffset), io.SeekStart)
	if err != nil {
		return nil, err
	}

	// encrypted index table bytes
	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	indexTable, err := types.DecryptIndexTableFromCipher(fek[:], header.IndexTableNonce[:], ciphertext)
	if err != nil {
		return nil, err
	}

	return indexTable, nil
}
