package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/0x0FACED/uuid"
	"github.com/0x0FACED/zec/pkg/core/progress"
	"github.com/0x0FACED/zec/pkg/core/v1/crypto"
)

// default params for argon
const (
	ArgonMemoryLog2  = 18
	ArgonIterations  = 5
	ArgonParallelism = 1
)

type SecretFile struct {
	f          *os.File
	header     Header     // file header
	indexTable IndexTable // index table
	masterKey  [32]byte

	mu sync.Mutex
}

func NewSecretFile(path string, password []byte) (*SecretFile, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	salt, err := crypto.Salt16()
	if err != nil {
		return nil, err
	}

	masterKey := crypto.Argon2idMasterKey32(password, salt, ArgonMemoryLog2, ArgonIterations, ArgonParallelism)

	encryptedFEK, err := crypto.EncryptFEK(masterKey)
	if err != nil {
		return nil, err
	}

	ownerID := uuid.NewV4()
	now := time.Now().Unix()

	indexTableNonce, err := crypto.Nonce12()
	if err != nil {
		return nil, err
	}

	header := Header{
		Version:          0x01,            // file format version
		Flags:            0x00,            // write not complete
		EncryptionAlgo:   AlgoChacha20,    // default algorithm
		ArgonMemoryLog2:  ArgonMemoryLog2, // 256 KiB memory, 1<<ArgonMemoryLog2
		SecretCount:      0x00,
		CreatedAt:        now,
		ModifiedAt:       now,
		DataSize:         0x00,
		OwnerID:          ownerID,
		ArgonSalt:        salt,
		ArgonIterations:  ArgonIterations,
		ArgonParallelism: ArgonParallelism,
		Checksum:         [32]byte{},
		VerificationTag:  [16]byte{},
		EncryptedFEK:     encryptedFEK,
		IndexTableOffset: 0x00,
		IndexTableNonce:  indexTableNonce,
		Reserved:         [60]byte{},
	}

	verificationTag := crypto.HMAC([32]byte(masterKey), header.AuthenticatedBytes())

	header.VerificationTag = verificationTag
	sf := &SecretFile{
		f:         f,
		masterKey: [32]byte(masterKey),
		header:    header,
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

func (sf *SecretFile) SetMasterKey(masterKey []byte) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.masterKey = [32]byte(masterKey)
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

// ExistsSecret checks if secret with provided name already exists.
func (sf *SecretFile) ExistsSecret(meta *SecretMeta) bool {
	for _, v := range sf.indexTable.Secrets {
		if v.Name == meta.Name {
			return true
		}
	}

	return false
}

func (sf *SecretFile) WriteSecret(meta SecretMeta, data io.Reader) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	if sf.ExistsSecret(&meta) {
		return errors.New("secret with provided name already exists")
	}
	// zip + compress
	dataBytes := StreamToByte(data)

	// zip
	/*compressed, err := crypto.Compress(dataBytes)
	if err != nil {
		return err
	}*/

	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag, sf.header.AuthenticatedBytes())
	if err != nil {
		return err
	}

	nonce, err := crypto.Nonce12()
	if err != nil {
		return err
	}
	// encrypt
	encrypted, err := crypto.EncryptChaCha20Poly1305(fek[:], nonce[:], dataBytes)

	payloadEnd := sf.payloadEndOffset()

	offset, err := sf.f.Seek(int64(payloadEnd), io.SeekStart)
	if err != nil {
		return err
	}

	meta.Offset = uint64(offset)
	meta.CreatedAt = uint64(time.Now().Unix())
	meta.ModifiedAt = meta.CreatedAt
	copy(meta.Nonce[:], nonce[:12])
	meta.EncryptMode = EncryptModeChaCha20Poly1305
	// change
	meta.Flags = FlagUndefined

	bar := progress.NewPrettyProgressBar("writing encrypted data", int64(len(encrypted)))
	n, err := io.Copy(io.MultiWriter(sf.f, bar), bytes.NewReader(encrypted))
	if err != nil {
		return err
	}

	meta.Size = uint64(n)
	meta.Flags = FlagCompleted | FlagEncrypted
	sf.indexTable.Secrets = append(sf.indexTable.Secrets, meta)
	sf.header.SecretCount++
	sf.header.ModifiedAt = time.Now().Unix()
	sf.header.DataSize += uint64(n)

	return nil
}

// WriteSecretFromReader used for writing files.
// Uses 24 byte nonce for xChaCha20.
func (sf *SecretFile) WriteSecretFromReader(meta SecretMeta, r io.Reader) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag, sf.header.AuthenticatedBytes())
	if err != nil {
		return err
	}

	nonce, err := crypto.Nonce24()
	if err != nil {
		return err
	}
	copy(meta.Nonce[:], nonce[:24])
	meta.Flags = FlagUndefined
	meta.EncryptMode = EncryptModeChaCha20Poly1305

	offset, err := sf.f.Seek(int64(sf.payloadEndOffset()), io.SeekStart)
	if err != nil {
		return err
	}
	meta.Offset = uint64(offset)

	reader := io.LimitReader(r, int64(meta.Size))
	bar := progress.NewPrettyProgressBar("encrypting data", int64(meta.Size))
	progressReader := io.TeeReader(reader, bar)

	err = crypto.EncryptXChaCha20Poly1305(fek[:], nonce[:], progressReader, sf.f)
	if err != nil {
		return err
	}

	endOffset, err := sf.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	meta.Size = uint64(endOffset - offset)

	now := uint64(time.Now().Unix())
	meta.CreatedAt = now
	meta.ModifiedAt = now
	meta.Flags = FlagCompleted | FlagEncrypted
	meta.EncryptMode = EncryptModeXChaCha20Poly1305

	sf.indexTable.Secrets = append(sf.indexTable.Secrets, meta)
	sf.header.SecretCount++
	sf.header.ModifiedAt = int64(now)
	sf.header.DataSize += meta.Size

	return nil
}

// move
func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(stream)
	return buf.Bytes()
}

// ReadSecret reads secret using decryption with chacha20 (nonce size is 12)
func (sf *SecretFile) ReadSecret(name string) (SecretData, error) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	stepBar := progress.NewStepBar("converting name to bytes", 1)
	// get [16]byte name from string name
	nameBytes, err := stringToBytes(name)
	if err != nil {
		return SecretData{}, err
	}
	stepBar.Add(1)

	stepBar = progress.NewStepBar("decrypting FEK", 1)
	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag, sf.header.AuthenticatedBytes())
	if err != nil {
		return SecretData{}, err
	}
	stepBar.Add(1)

	// search for correct secret meta
	var meta *SecretMeta
	for i := range sf.indexTable.Secrets {
		if sf.indexTable.Secrets[i].Name == nameBytes {
			meta = &sf.indexTable.Secrets[i]
			break
		}
	}

	// not found -> no secret with provided id
	if meta == nil {
		return SecretData{}, errors.New("secret not found")
	}

	// seek file ptr to offset and create buffer for secret
	encryptedBuf := make([]byte, meta.Size)
	_, err = sf.f.Seek(int64(meta.Offset), io.SeekStart)
	if err != nil {
		return SecretData{}, err
	}

	reader := io.LimitReader(sf.f, int64(meta.Size))
	bar := progress.NewPrettyProgressBar("reading secret", int64(meta.Size))
	progressReader := io.TeeReader(reader, bar)
	// read secret
	_, err = io.ReadFull(progressReader, encryptedBuf)
	if err != nil {
		return SecretData{}, err
	}

	stepBar = progress.NewStepBar("decrypting data", 1)
	secretData, err := crypto.DecryptChaCha20Poly1305(fek[:], meta.Nonce[:12], encryptedBuf)
	if err != nil {
		return SecretData{}, err
	}
	stepBar.Add(1)

	// return secret
	return SecretData{
		Meta: *meta,
		Val:  secretData,
	}, nil
}

func (sf *SecretFile) ReadSecretToWriter(name string, w io.Writer) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	stepBar := progress.NewStepBar("converting name to bytes", 1)
	nameBytes, err := stringToBytes(name)
	if err != nil {
		return err
	}
	stepBar.Add(1)

	stepBar = progress.NewStepBar("decrypting FEK", 1)
	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag, sf.header.AuthenticatedBytes())
	if err != nil {
		return err
	}
	stepBar.Add(1)

	var meta *SecretMeta
	for i := range sf.indexTable.Secrets {
		if sf.indexTable.Secrets[i].Name == nameBytes {
			meta = &sf.indexTable.Secrets[i]
			break
		}
	}
	if meta == nil {
		return errors.New("secret not found")
	}

	_, err = sf.f.Seek(int64(meta.Offset), io.SeekStart)
	if err != nil {
		return err
	}

	reader := io.LimitReader(sf.f, int64(meta.Size))
	bar := progress.NewPrettyProgressBar("decrypting data", int64(meta.Size))
	progressReader := io.TeeReader(reader, bar)

	err = crypto.DecryptXChaCha20Poly1305(fek[:], meta.Nonce[:], progressReader, w)
	if err != nil {
		return err
	}

	return nil
}

// DeleteSecretSoft marks secret as deleted (FlagDeleted)
func (sf *SecretFile) DeleteSecretSoft(name string) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	stepBar := progress.NewStepBar("converting name to bytes", 1)
	nameBytes, err := stringToBytes(name)
	if err != nil {
		return err
	}
	stepBar.Add(1)

	meta, err := sf.indexTable.SecretByName(nameBytes)
	if err != nil {
		return err
	}

	// mark as deleted
	meta.Flags |= FlagDeleted
	// update modify time
	meta.ModifiedAt = uint64(time.Now().Unix())

	return nil
}

func (sf *SecretFile) Save() error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	fullProgressBar := progress.NewStepBar("saving file", 6)

	payloadEnd := sf.payloadEndOffset()

	// write index table
	if _, err := sf.f.Seek(int64(payloadEnd), io.SeekStart); err != nil {
		return fmt.Errorf("seek for index table failed: %w", err)
	}

	sf.header.IndexTableOffset = payloadEnd
	stepBar := progress.NewStepBar("re-calculating HMAC", 1)
	sf.header.VerificationTag = crypto.HMAC(sf.masterKey, sf.header.AuthenticatedBytes())

	stepBar.Add(1)
	fullProgressBar.Add(1)

	stepBar = progress.NewStepBar("re-writing index table", 1)
	err := sf.writeIndexTable()
	if err != nil {
		return err
	}

	stepBar.Add(1)
	fullProgressBar.Add(1)

	_, err = sf.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	// set up all flags
	sf.header.Flags = FlagCompleted | FlagEncrypted

	_, err = sf.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	stepBar = progress.NewStepBar("[1/2] re-writing header", 1)
	err = sf.writeHeader()
	if err != nil {
		return err
	}

	stepBar.Add(1)
	fullProgressBar.Add(1)

	stepBar = progress.NewStepBar("calculating checksum", 1)
	checksum, err := sf.calculateChecksum()
	if err != nil {
		return err
	}

	stepBar.Add(1)
	fullProgressBar.Add(1)

	sf.header.Checksum = checksum

	_, err = sf.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	stepBar = progress.NewStepBar("[2/2] re-writing header", 1)
	// update header
	err = sf.writeHeader()
	if err != nil {
		return err
	}

	stepBar.Add(1)
	fullProgressBar.Add(1)

	stepBar = progress.NewStepBar("syncing file", 1)
	if err := sf.f.Sync(); err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	stepBar.Add(1)
	fullProgressBar.Add(1)

	// close file after writing header
	return sf.f.Close()
}

func (sf *SecretFile) payloadEndOffset() uint64 {
	var max uint64 = HEADER_SIZE

	for _, s := range sf.indexTable.Secrets {
		if end := s.Offset + s.Size; end > max {
			max = end
		}
	}

	return max
}

func (sf *SecretFile) ValidateChecksum() error {
	want := sf.header.Checksum

	stepBar := progress.NewStepBar("calculating checksum", 1)
	fact, err := sf.calculateChecksum()
	if err != nil {
		return err
	}
	stepBar.Add(1)

	// fmt.Println("Want: ", want)
	// fmt.Println("Fact: ", fact)

	if want != fact {
		return errors.New("checksum is not valid")
	}

	return nil
}

func (sf *SecretFile) calculateChecksum() ([32]byte, error) {
	hasher, err := sf.calculateHeaderChecksum()
	if err != nil {
		return [32]byte{}, err
	}

	const (
		startPosition = HEADER_SIZE
		blockSize     = 4 * 1024 // 4KB
	)

	if _, err := sf.f.Seek(startPosition, io.SeekStart); err != nil {
		return [32]byte{}, err
	}

	buf := make([]byte, blockSize)

	for {
		n, err := sf.f.Read(buf)
		if n > 0 {
			_, err = hasher.Write(buf)
		}
		if err == io.EOF || n == 0 {
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

func (sf *SecretFile) calculateHeaderChecksum() (hash.Hash, error) {
	const (
		checksumOffset        = 68 // checksum starts from 68 offset
		checksumSize          = 32 // checksum size always is 32 bytes
		bufSizeBeforeChecksum = HEADER_SIZE - (HEADER_SIZE - checksumOffset)
		bufSizeAfterChecksum  = HEADER_SIZE - (checksumOffset + checksumSize)
	)

	ret, err := sf.f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if ret != 0 {
		return nil, errors.New("start position for hashing header must be 0")
	}

	hasher := sha256.New()

	bufBeforeChecksum := make([]byte, bufSizeBeforeChecksum)

	n, err := sf.f.Read(bufBeforeChecksum)
	if err == io.EOF || n == 0 {
		return nil, errors.New("unexpected EOF")
	}

	if err != nil {
		return nil, err
	}

	// write bytes before checksum
	_, err = hasher.Write(bufBeforeChecksum)

	emptyChecksum := make([]byte, checksumSize)

	// writing arr{0,0,0,...,0} as checksum
	_, err = hasher.Write(emptyChecksum)

	ret, err = sf.f.Seek(checksumOffset+checksumSize, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if ret != checksumOffset+checksumSize {
		return nil, errors.New("start position for hashing header after checksum must be " + strconv.Itoa(checksumOffset+checksumSize))
	}

	bufAfterChecksum := make([]byte, bufSizeAfterChecksum)

	n, err = sf.f.Read(bufAfterChecksum)
	if err == io.EOF || n == 0 {
		return nil, errors.New("unexpected EOF")
	}

	if err != nil {
		return nil, err
	}

	// write bytes after checksum
	_, err = hasher.Write(bufAfterChecksum)

	return hasher, nil
}

func (sf *SecretFile) writeIndexTable() error {
	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag, sf.header.AuthenticatedBytes())
	if err != nil {
		return err
	}

	ciphertext, err := sf.indexTable.Encrypt(fek[:], sf.header.IndexTableNonce[:])
	if err != nil {
		return err
	}

	if _, err := sf.f.Write(ciphertext); err != nil {
		return err
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
