package types

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

type SecretFile struct {
	f          *os.File
	header     Header     // file header
	indexTable IndexTable // index table

	mu sync.Mutex
}

func NewSecretFile(path string, ownerID [16]byte) (*SecretFile, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	sf := &SecretFile{
		f: f,
		header: Header{
			Version:          0x01,         // file version
			CompleteFlag:     0x00,         // did write complete (default to 0 - not complete)
			EncryptionAlgo:   AlgoChacha20, // default to chacha20
			SecretCount:      0x00,
			CreatedAt:        time.Now().Unix(),
			ModifiedAt:       time.Now().Unix(),
			DataSize:         0x00, // default to 0
			OwnerID:          ownerID,
			Nonce:            [12]byte{},
			Checksum:         [32]byte{},
			IndexTableOffset: 0x00, // default to 0
			Reserved:         [24]byte{},
		},
		indexTable: IndexTable{
			Secrets: []SecretMeta{},
		},
	}

	if err := sf.writeHeader(); err != nil {
		return nil, err
	}

	return sf, nil
}

func (sf *SecretFile) SetHeader(header Header) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.header = header
}

func (sf *SecretFile) Header() Header {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	return sf.header
}

func (sf *SecretFile) SetIndexTable(indexTable IndexTable) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.indexTable = indexTable
}

func (sf *SecretFile) IndexTable() IndexTable {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	return sf.indexTable
}

func (sf *SecretFile) SetFile(f *os.File) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.f = f
}

func (sf *SecretFile) File() *os.File {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	return sf.f
}

func (sf *SecretFile) Close() error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	if err := sf.f.Close(); err != nil {
		return err
	}

	return nil
}

func (sf *SecretFile) WriteSecret(meta SecretMeta, data io.Reader) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	offset, err := sf.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	meta.Offset = uint64(offset)
	meta.CreatedAt = uint64(time.Now().Unix())
	meta.ModifiedAt = meta.CreatedAt

	// change
	meta.Flags = FlagUndefined

	n, err := io.Copy(sf.f, data)
	if err != nil {
		return err
	}

	meta.Size = uint64(n)
	sf.indexTable.Secrets = append(sf.indexTable.Secrets, meta)
	sf.header.SecretCount++
	sf.header.ModifiedAt = time.Now().Unix()
	sf.header.DataSize += uint64(n)

	// at the end of writing change flag

	return nil
}

func (sf *SecretFile) ReadSecret(id string) (SecretData, error) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	// get [16]byte id from string id
	idBytes, err := stringToBytes(id)
	if err != nil {
		return SecretData{}, err
	}

	// search for correct secret meta
	var meta *SecretMeta
	for i := range sf.indexTable.Secrets {
		if sf.indexTable.Secrets[i].ID == idBytes {
			meta = &sf.indexTable.Secrets[i]
			break
		}
	}

	// not found -> no secret with provided id
	if meta == nil {
		return SecretData{}, errors.New("secret not found")
	}

	// seek file ptr to offset and create buffer for secret
	buf := make([]byte, meta.Size)
	_, err = sf.f.Seek(int64(meta.Offset), io.SeekStart)
	if err != nil {
		return SecretData{}, err
	}

	// read secret
	_, err = io.ReadFull(sf.f, buf)
	if err != nil {
		return SecretData{}, err
	}

	// return secret
	return SecretData{
		Meta: *meta,
		Val:  buf,
	}, nil
}

func (sf *SecretFile) Save() error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	// write index table
	indexTableOffset, err := sf.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	sf.header.IndexTableOffset = uint64(indexTableOffset)
	err = sf.writeIndexTable()
	if err != nil {
		return err
	}

	if _, err := sf.f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// set up all flags
	sf.header.CompleteFlag = FlagCompleted | FlagEncrypted | FlagCompressed

	err = sf.writeHeader()
	if err != nil {
		return err
	}

	return nil
}

func (sf *SecretFile) writeIndexTable() error {
	for _, meta := range sf.indexTable.Secrets {
		if err := binary.Write(sf.f, binary.LittleEndian, meta); err != nil {
			return err
		}
	}
	return nil
}

func (sf *SecretFile) writeHeader() error {
	err := binary.Write(sf.f, binary.LittleEndian, sf.header)
	if err != nil {
		return err
	}

	return err
}
