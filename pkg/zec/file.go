package zec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/0x0FACED/zec/pkg/zec/helpers"
)

const (
	BlockSize = 4096 * 1024 // 4mb
)

// FileStorage файловая реализация интерфейса Storage
type FileStorage struct {
	file    *os.File
	header  Header
	index   *IndexTable
	session *Session
	dirty   bool // нужно ли сохранение
}

func NewFileStorage(path string) (*FileStorage, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	return &FileStorage{
		file:  file,
		index: &IndexTable{secrets: make([]SecretMeta, 0)},
	}, nil
}

func OpenFileStorage(path string) (*FileStorage, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	storage := &FileStorage{
		file:  file,
		index: &IndexTable{secrets: make([]SecretMeta, 0)},
	}

	if err := storage.readHeader(); err != nil {
		file.Close()
		return nil, err
	}

	if storage.header.SecretCount > 0 {
		if err := storage.readIndex(); err != nil {
			file.Close()
			return nil, err
		}
	}

	return storage, nil
}

func (fs *FileStorage) Initialize(header Header) error {
	fs.header = header
	fs.dirty = true
	return fs.writeHeader()
}

func (fs *FileStorage) GetHeader() (Header, error) {
	return fs.header, nil
}

func (fs *FileStorage) UpdateHeader(header Header) error {
	fs.header = header
	fs.dirty = true
	return nil
}

func (fs *FileStorage) ListSecrets() ([]SecretMeta, error) {
	var secrets []SecretMeta
	for _, meta := range fs.index.secrets {
		secrets = append(secrets, meta)
	}
	return secrets, nil
}

func (fs *FileStorage) DeleteSecretSoft(name string) error {
	nameBytes, err := helpers.ConvertStringNameToBytes32(name)
	if err != nil {
		return err
	}

	// get secret meta
	meta, err := fs.index.SecretByName(nameBytes)
	if err != nil {
		return err
	}

	meta.Flags |= FlagDeleted
	meta.ModifiedAt = uint64(time.Now().Unix())

	fs.dirty = true
	return nil
}

func (fs *FileStorage) ExistsSecret(name [32]byte) bool {
	for _, v := range fs.index.secrets {
		if v.Name == name {
			return true
		}
	}

	return false
}

func (fs *FileStorage) DeleteSecretHard(name string) error {
	nameBytes, err := helpers.ConvertStringNameToBytes32(name)
	if err != nil {
		return err
	}

	// get secret meta
	meta, err := fs.index.SecretByName(nameBytes)
	if err != nil {
		return err
	}

	// remember offset and size
	delOffset := meta.Offset
	delSize := meta.Size

	// zero buf that will replace secret blocks
	zeroBuf := make([]byte, BlockSize)
	// remain bytes to replace
	remain := delSize
	// current position
	pos := delOffset

	// for there are remain secret blocks
	for remain > 0 {
		toWrite := BlockSize
		if remain < uint64(BlockSize) {
			toWrite = int(remain)
		}

		// seek ptr to secret we want delete
		_, err := fs.file.Seek(int64(pos), io.SeekStart)
		if err != nil {
			return err
		}

		// write zero buf
		nWritten, err := fs.file.Write(zeroBuf[:toWrite])
		if err != nil {
			return err
		}
		// if not equal - there is corrupted file
		if nWritten != toWrite {
			return errors.New("file corrupted during zeroing")
		}

		// update pos and remain
		pos += uint64(nWritten)
		remain -= uint64(nWritten)
	}

	// get index if next secret
	nextIdx, err := fs.index.NextSecretIdx(nameBytes)
	if err != nil {
		return err
	}

	// buf for reading/writing secret blocks after deleted secrets
	readBuf := make([]byte, BlockSize)
	writePtr := delOffset

	nWritten := uint64(0)
	for i := nextIdx; i < len(fs.index.secrets); i++ {
		// get ptr to next secret
		s := &fs.index.secrets[i]
		originalOffset := s.Offset
		originalSize := s.Size
		remain := originalSize
		// we read from s.Offset
		readPos := originalOffset
		// and write to delOffset + nWritten
		writePos := delOffset + nWritten

		// loop that rewrites secret by blocks
		for remain > 0 {
			// calt block size
			toRead := BlockSize
			if remain < uint64(BlockSize) {
				toRead = int(remain)
			}

			// seek ptr to read next secret block
			_, err := fs.file.Seek(int64(readPos), io.SeekStart)
			if err != nil {
				return err
			}
			// read block
			nRead, err := fs.file.Read(readBuf[:toRead])
			if err != nil {
				return err
			}
			// cmp read bytes and toRead bytes
			if nRead != toRead {
				return errors.New("file corrupted during reverse read")
			}

			// seek ptr to write pos
			_, err = fs.file.Seek(int64(writePos), io.SeekStart)
			if err != nil {
				return err
			}

			// write block that we read before
			written, err := fs.file.Write(readBuf[:toRead])
			if err != nil {
				return err
			}
			// cmp
			if written != toRead {
				return errors.New("file corrupted during reverse write")
			}
			// update all written bytes
			nWritten += uint64(written)
			// update read pos for next block of data
			readPos += uint64(nRead)
			//writePos += originalOffset + (originalSize - (originalSize - remain))
			// update writePos
			writePos += nWritten
			// update remain with actually read bytes
			remain -= uint64(nRead)
		}

		// set new offset for next secret and modified at
		s.Offset = writePtr
		// mb will be removed
		s.ModifiedAt = uint64(time.Now().Unix())
		// update writePtr
		writePtr += originalSize
	}

	// remove meta data of secret from index table
	err = fs.index.RemoveByName(nameBytes)
	if err != nil {
		return err
	}

	// calc end of secrets
	// mb replace with fs.payloadEndOffset()
	var maxEnd uint64
	for _, s := range fs.index.secrets {
		end := s.Offset + s.Size
		if end > maxEnd {
			maxEnd = end
		}
	}

	// update header fields
	fs.header.DataSize -= delSize
	fs.header.ModifiedAt = time.Now().Unix()
	fs.header.SecretCount--

	// cut redundant bytes `trash` bytes in file
	err = fs.file.Truncate(int64(maxEnd))
	if err != nil {
		return fmt.Errorf("truncate failed: %w", err)
	}

	fs.dirty = true
	return nil
}

func (fs *FileStorage) GetDataReader(offset, size uint64) (io.ReadCloser, error) {
	file, err := os.Open(fs.file.Name())
	if err != nil {
		return nil, err
	}

	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}

	return &limitedReadCloser{
		ReadCloser: file,
		remaining:  int64(size),
	}, nil
}

func (fs *FileStorage) GetDataWriter() (io.WriteCloser, uint64, error) {
	offset := fs.calculateDataEnd()

	if _, err := fs.file.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, 0, err
	}

	return &fileWriteCloser{file: fs.file}, offset, nil
}

func (fs *FileStorage) Save() error {
	// этот метод крайне важен, его надо перепроверить еще раз и сравнить в текущей реализацией save
	if !fs.dirty {
		return nil
	}

	dataEnd := fs.calculateDataEnd()
	fs.header.IndexTableOffset = dataEnd

	if err := fs.writeIndex(); err != nil {
		return err
	}

	if err := fs.calculateAndWriteChecksum(); err != nil {
		return err
	}

	if err := fs.file.Sync(); err != nil {
		return err
	}

	fs.dirty = false
	return nil
}

func (fs *FileStorage) Close() error {
	if fs.dirty {
		if err := fs.Save(); err != nil {
			return err
		}
	}
	return fs.file.Close()
}

func (fs *FileStorage) ValidateChecksum() error {
	// чек сам не считается еще, надо перенести реализацию
	calculated, err := fs.calculateChecksum()
	if err != nil {
		return err
	}

	if calculated != fs.header.Checksum {
		return ErrChecksumMismatch
	}

	return nil
}

func (fs *FileStorage) readHeader() error {
	if _, err := fs.file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	return binary.Read(fs.file, binary.LittleEndian, &fs.header)
}

func (fs *FileStorage) writeHeader() error {
	if _, err := fs.file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	return binary.Write(fs.file, binary.LittleEndian, &fs.header)
}

func (fs *FileStorage) readIndex() error {
	if _, err := fs.file.Seek(int64(fs.header.IndexTableOffset), io.SeekStart); err != nil {
		return err
	}

	encryptedData, err := io.ReadAll(fs.file)
	if err != nil {
		return err
	}

	// нормально реализовать, потому что здесь херня, надо как-то сюда перетащить реализацию
	return fs.index.deserialize(encryptedData)
}

func (fs *FileStorage) writeIndex() error {
	if _, err := fs.file.Seek(int64(fs.header.IndexTableOffset), io.SeekStart); err != nil {
		return err
	}

	// TODO: Перетащить аналогчно реализацию
	data, err := fs.index.serialize(fs.session.fek[:], fs.session.masterKey[:])
	if err != nil {
		return err
	}

	_, err = fs.file.Write(data)
	return err
}

func (fs *FileStorage) calculateDataEnd() uint64 {
	var maxEnd uint64 = HEADER_SIZE

	for _, meta := range fs.index.secrets {
		if meta.Flags&FlagDeleted == 0 {
			end := meta.Offset + meta.Size
			if end > maxEnd {
				maxEnd = end
			}
		}
	}

	return maxEnd
}

func (fs *FileStorage) calculateChecksum() ([32]byte, error) {
	hasher, err := fs.calculateHeaderChecksum()
	if err != nil {
		return [32]byte{}, err
	}

	const (
		startPosition = HEADER_SIZE
		blockSize     = 4 * 1024 // 4KB
	)

	if _, err := fs.file.Seek(startPosition, io.SeekStart); err != nil {
		return [32]byte{}, err
	}

	buf := make([]byte, blockSize)

	for {
		n, err := fs.file.Read(buf)
		if n > 0 {
			// write only n bytes (if n < blockSize)
			if _, werr := hasher.Write(buf[:n]); werr != nil {
				return [32]byte{}, werr
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return [32]byte{}, err
		}
	}

	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result, nil
}

func (fs *FileStorage) calculateAndWriteChecksum() error {
	fs.header.Checksum = [32]byte{}
	if err := fs.writeHeader(); err != nil {
		return err
	}

	checksum, err := fs.calculateChecksum()
	if err != nil {
		return err
	}

	fs.header.Checksum = checksum
	return fs.writeHeader()
}

func (sf *FileStorage) calculateHeaderChecksum() (hash.Hash, error) {
	const (
		checksumOffset        = 68 // checksum starts from 68 offset
		checksumSize          = 32 // checksum size always is 32 bytes
		bufSizeBeforeChecksum = HEADER_SIZE - (HEADER_SIZE - checksumOffset)
		bufSizeAfterChecksum  = HEADER_SIZE - (checksumOffset + checksumSize)
	)

	ret, err := sf.file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if ret != 0 {
		return nil, errors.New("start position for hashing header must be 0")
	}

	hasher := sha256.New()

	bufBeforeChecksum := make([]byte, bufSizeBeforeChecksum)

	n, err := sf.file.Read(bufBeforeChecksum)
	if err == io.EOF || n == 0 {
		return nil, errors.New("unexpected EOF")
	}

	if err != nil {
		return nil, err
	}

	// write bytes before checksum
	_, err = hasher.Write(bufBeforeChecksum)
	if err != nil {
		return nil, err
	}

	emptyChecksum := make([]byte, checksumSize)

	// writing arr{0,0,0,...,0} as checksum
	_, err = hasher.Write(emptyChecksum)
	if err != nil {
		return nil, err
	}

	ret, err = sf.file.Seek(checksumOffset+checksumSize, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if ret != checksumOffset+checksumSize {
		return nil, errors.New("start position for hashing header after checksum must be " + strconv.Itoa(checksumOffset+checksumSize))
	}

	bufAfterChecksum := make([]byte, bufSizeAfterChecksum)

	n, err = sf.file.Read(bufAfterChecksum)
	if err == io.EOF || n == 0 {
		return nil, errors.New("unexpected EOF")
	}

	if err != nil {
		return nil, err
	}

	// write bytes after checksum
	_, err = hasher.Write(bufAfterChecksum)
	if err != nil {
		return nil, err
	}

	return hasher, nil
}

type IndexTable struct {
	secrets []SecretMeta
}

func (it IndexTable) Secrets() []SecretMeta {
	return it.secrets
}

func (it IndexTable) SecretByName(name [32]byte) (*SecretMeta, error) {
	for i := range it.secrets {
		if it.secrets[i].Name == name {
			return &it.secrets[i], nil
		}
	}

	return nil, errors.New("secret not found")
}

func (it *IndexTable) NextSecretIdx(name [32]byte) (int, error) {
	for i := range it.secrets {
		if it.secrets[i].Name == name {
			if i < len(it.secrets) {
				return i + 1, nil
			}

			return -1, errors.New("no next secrets")
		}
	}

	return -1, errors.New("secret not found")
}

func (it *IndexTable) RemoveByName(name [32]byte) error {
	for i, s := range it.secrets {
		if s.Name == name {
			if i < len(it.secrets) {
				it.secrets = slices.Delete(it.secrets, i, i+1)
				return nil
			}

			return errors.New("no next secrets")
		}
	}

	return errors.New("secret not found")
}

func (it *IndexTable) serialize(fek []byte, nonce []byte) ([]byte, error) {
	// TODO: Вот это переписать надо из индекс тейбла
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	if err := encoder.Encode(it.secrets); err != nil {
		return nil, err
	}

	var dst bytes.Buffer

	cipher := NewChaCha20Cipher()

	_, err := cipher.Encrypt(fek, nonce, &buf, &dst, EncryptModeChaCha20)
	if err != nil {
		return nil, err
	}

	return dst.Bytes(), nil
}

func (it *IndexTable) deserialize(data []byte) error {
	// TODO: Вот это переписать надо из индекс тейбла
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)

	var secrets []SecretMeta
	if err := decoder.Decode(&secrets); err != nil {
		return err
	}

	// Загружаем в map
	it.secrets = make([]SecretMeta, len(secrets))
	for i, meta := range secrets {
		it.secrets[i] = meta
	}

	return nil
}

type limitedReadCloser struct {
	io.ReadCloser
	remaining int64
}

func (lr *limitedReadCloser) Read(p []byte) (n int, err error) {
	if lr.remaining <= 0 {
		return 0, io.EOF
	}

	if int64(len(p)) > lr.remaining {
		p = p[0:lr.remaining]
	}

	n, err = lr.ReadCloser.Read(p)
	lr.remaining -= int64(n)
	return
}

type fileWriteCloser struct {
	file *os.File
}

func (fw *fileWriteCloser) Write(p []byte) (n int, err error) {
	return fw.file.Write(p)
}

func (fw *fileWriteCloser) Close() error {
	return fw.file.Sync()
}
