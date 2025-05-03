package file

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/0x0FACED/zec/pkg/core/v1/types"
)

func Open(path string) (*types.SecretFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	// Read the header
	header := types.Header{}
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	// get index table offset
	indexTableOffset := header.IndexTableOffset

	// set seek to the index table offset
	ret, err := f.Seek(int64(indexTableOffset), io.SeekStart)
	if err != nil {
		return nil, err
	}

	// ret must be equal to indexTableOffset
	// TODO: remove
	fmt.Println("ret", ret)
	fmt.Println("indexTableOffset", indexTableOffset)

	// Read the index table
	indexTable, err := ReadIndexTable(f, &header)
	if err != nil {
		return nil, err
	}

	// we dont read secrets. we only read header and index table
	// so its secured
	// Create the SecretFile struct
	secretFile := &types.SecretFile{}

	secretFile.SetFile(f)
	secretFile.SetHeader(header)
	secretFile.SetIndexTable(*indexTable)

	return secretFile, nil
}

func ReadIndexTable(f *os.File, header *types.Header) (*types.IndexTable, error) {
	// set read to IndexTableOffset
	_, err := f.Seek(int64(header.IndexTableOffset), io.SeekStart)
	if err != nil {
		return nil, err
	}

	// get size of every meta block (size-fixed)
	metaSize := binary.Size(types.SecretMeta{})
	if metaSize <= 0 {
		return nil, errors.New("invalid SecretMeta size")
	}

	// count full size of index table
	totalSize := int(header.SecretCount) * metaSize
	// make buf for index table
	buf := make([]byte, totalSize)

	// read full index table
	_, err = io.ReadFull(f, buf)
	if err != nil {
		return nil, err
	}

	// make slice of secrets metadata of header.SecretCount size
	metas := make([]types.SecretMeta, header.SecretCount)
	var i uint32
	// iterate over all secrets
	for i = 0; i < header.SecretCount; i++ {
		// every itaration - read new block from buf
		offset := i * uint32(metaSize)
		metaBuf := buf[offset : offset+uint32(metaSize)]

		// read block from metaBuf and write fo metas[i]
		err := binary.Read(
			bytes.NewReader(metaBuf),
			binary.LittleEndian,
			&metas[i],
		)
		if err != nil {
			return nil, err
		}
	}

	// create index table from metas slice
	indexTable := types.IndexTable{
		Secrets: metas,
	}

	return &indexTable, nil
}
