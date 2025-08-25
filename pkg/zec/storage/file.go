package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"io"
	"os"
	"time"

	"github.com/0x0FACED/zec/pkg/zec"
)

// FileStorage файловая реализация интерфейса Storage
type FileStorage struct {
	file   *os.File
	header zec.Header
	index  *IndexTable
	dirty  bool // нужно ли сохранение
}

func NewFileStorage(path string) (*FileStorage, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	return &FileStorage{
		file:  file,
		index: &IndexTable{secrets: make(map[string]zec.SecretMeta)},
	}, nil
}

func OpenFileStorage(path string) (*FileStorage, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	storage := &FileStorage{
		file:  file,
		index: &IndexTable{secrets: make(map[string]zec.SecretMeta)},
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

func (fs *FileStorage) Initialize(header zec.Header) error {
	fs.header = header
	fs.dirty = true
	return fs.writeHeader()
}

func (fs *FileStorage) GetHeader() (zec.Header, error) {
	return fs.header, nil
}

func (fs *FileStorage) UpdateHeader(header zec.Header) error {
	fs.header = header
	fs.dirty = true
	return nil
}

func (fs *FileStorage) SecretExists(name string) (bool, error) {
	meta, exists := fs.index.secrets[name]
	return exists && (meta.Flags&zec.FlagDeleted == 0), nil
}

func (fs *FileStorage) GetSecretMeta(name string) (zec.SecretMeta, error) {
	meta, exists := fs.index.secrets[name]
	if !exists {
		return zec.SecretMeta{}, zec.ErrSecretNotFound
	}
	return meta, nil
}

func (fs *FileStorage) AddSecretMeta(meta zec.SecretMeta) error {
	fs.index.secrets[meta.Name] = meta

	fs.header.SecretCount++
	fs.header.DataSize += meta.Size
	fs.header.ModifiedAt = time.Now().Unix()

	fs.dirty = true
	return nil
}

func (fs *FileStorage) ListSecrets() ([]zec.SecretMeta, error) {
	var secrets []zec.SecretMeta
	for _, meta := range fs.index.secrets {
		secrets = append(secrets, meta)
	}
	return secrets, nil
}

func (fs *FileStorage) DeleteSecretSoft(name string) error {
	meta, exists := fs.index.secrets[name]
	if !exists {
		return zec.ErrSecretNotFound
	}

	meta.Flags |= zec.FlagDeleted
	meta.ModifiedAt = time.Now().Unix()
	fs.index.secrets[name] = meta

	fs.dirty = true
	return nil
}

func (fs *FileStorage) DeleteSecretHard(name string) error {
	meta, exists := fs.index.secrets[name]
	if !exists {
		return zec.ErrSecretNotFound
	}

	delete(fs.index.secrets, name)

	fs.header.SecretCount--
	fs.header.DataSize -= meta.Size
	fs.header.ModifiedAt = time.Now().Unix()

	// TODO: перетащить код из types.SecretFile, там уже есть првильное удалегние
	// Пока просто помечаем как удаленный

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
		return zec.ErrChecksumMismatch
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
	data, err := fs.index.serialize()
	if err != nil {
		return err
	}

	_, err = fs.file.Write(data)
	return err
}

func (fs *FileStorage) calculateDataEnd() uint64 {
	var maxEnd uint64 = zec.HEADER_SIZE

	for _, meta := range fs.index.secrets {
		if meta.Flags&zec.FlagDeleted == 0 {
			end := meta.Offset + meta.Size
			if end > maxEnd {
				maxEnd = end
			}
		}
	}

	return maxEnd
}

func (fs *FileStorage) calculateChecksum() ([32]byte, error) {
	// TODO: перетащить реализацию
	return [32]byte{}, nil
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

type IndexTable struct {
	secrets map[string]zec.SecretMeta
}

func (it IndexTable) Secrets() map[string]zec.SecretMeta {
	return it.secrets
}

func (it *IndexTable) serialize() ([]byte, error) {
	// TODO: Вот это переписать надо из индекс тейбла
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	var secrets []zec.SecretMeta
	for _, meta := range it.secrets {
		secrets = append(secrets, meta)
	}

	if err := encoder.Encode(secrets); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (it *IndexTable) deserialize(data []byte) error {
	// TODO: Вот это переписать надо из индекс тейбла
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)

	var secrets []zec.SecretMeta
	if err := decoder.Decode(&secrets); err != nil {
		return err
	}

	// Загружаем в map
	it.secrets = make(map[string]zec.SecretMeta)
	for _, meta := range secrets {
		it.secrets[meta.Name] = meta
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
