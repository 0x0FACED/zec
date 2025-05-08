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
	"github.com/0x0FACED/zec/pkg/core/v1/crypto"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/chacha20poly1305"
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

	verificationTag := crypto.HMAC([32]byte(masterKey))

	ownerID := uuid.NewV4()

	now := time.Now().Unix()

	indexTableNonce, err := crypto.Nonce12()
	if err != nil {
		return nil, err
	}

	sf := &SecretFile{
		f:         f,
		masterKey: [32]byte(masterKey),
		header: Header{
			Version:          0x01,            // file format version
			CompleteFlag:     0x00,            // write not complete
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
			VerificationTag:  verificationTag,
			EncryptedFEK:     encryptedFEK,
			IndexTableOffset: 0x00,
			IndexTableNonce:  indexTableNonce,
			Reserved:         [60]byte{},
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

func (sf *SecretFile) WriteSecret(meta SecretMeta, data io.Reader) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	// zip + compress
	dataBytes := StreamToByte(data)

	// zip
	/*compressed, err := crypto.Compress(dataBytes)
	if err != nil {
		return err
	}*/

	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag)
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
	meta.Nonce = nonce

	// change
	meta.Flags = FlagUndefined

	bar := progressbar.DefaultBytes(int64(len(encrypted)), "writing encrypted data")
	n, err := io.Copy(io.MultiWriter(sf.f, bar), bytes.NewReader(encrypted))
	if err != nil {
		return err
	}

	meta.Size = uint64(n)
	sf.indexTable.Secrets = append(sf.indexTable.Secrets, meta)
	sf.header.SecretCount++
	sf.header.ModifiedAt = time.Now().Unix()
	sf.header.DataSize += uint64(n)
	// at the end of writing change flag
	meta.Flags = FlagCompleted

	return nil
}

// WriteSecretFromReader used for writing files (works incorrectly)
func (sf *SecretFile) WriteSecretFromReader(meta SecretMeta, r io.Reader) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag)
	if err != nil {
		return err
	}

	nonce, err := crypto.Nonce12()
	if err != nil {
		return err
	}
	meta.Nonce = nonce

	offset, err := sf.f.Seek(int64(sf.payloadEndOffset()), io.SeekStart)
	if err != nil {
		return err
	}
	meta.Offset = uint64(offset)

	aead, err := chacha20poly1305.New(fek[:])
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()

	total := 0
	go func() {
		defer pw.Close()

		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				block := buf[:n]
				enc := aead.Seal(nil, nonce[:], block, nil)
				if _, err := pw.Write(enc); err != nil {
					return
				}
				total += len(enc)
			}
			if err == io.EOF {
				return
			}
			if err != nil {
				pw.CloseWithError(err)
				return
			}
		}
	}()

	nWritten, err := io.Copy(sf.f, pr)
	if err != nil {
		return err
	}
	meta.Size = uint64(nWritten)

	fmt.Println("Written: ", nWritten)
	fmt.Println("Encrypted: ", total)

	now := uint64(time.Now().Unix())
	meta.CreatedAt = now
	meta.ModifiedAt = now
	meta.Flags = FlagCompleted

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

func (sf *SecretFile) ReadSecret(id string) (SecretData, error) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	// get [16]byte id from string id
	idBytes, err := stringToBytes(id)
	if err != nil {
		return SecretData{}, err
	}

	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag)
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
	encryptedBuf := make([]byte, meta.Size)
	_, err = sf.f.Seek(int64(meta.Offset), io.SeekStart)
	if err != nil {
		return SecretData{}, err
	}

	// read secret
	_, err = io.ReadFull(sf.f, encryptedBuf)
	if err != nil {
		return SecretData{}, err
	}

	secretData, err := crypto.DecryptChaCha20Poly1305(fek[:], meta.Nonce[:], encryptedBuf)
	if err != nil {
		return SecretData{}, err
	}

	// return secret
	return SecretData{
		Meta: *meta,
		Val:  secretData,
	}, nil
}

func (sf *SecretFile) ReadSecretToWriter(id string, w io.Writer) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	idBytes, err := stringToBytes(id)
	if err != nil {
		return err
	}

	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag)
	if err != nil {
		return err
	}

	var meta *SecretMeta
	for i := range sf.indexTable.Secrets {
		if sf.indexTable.Secrets[i].ID == idBytes {
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

	bar := progressbar.DefaultBytes(int64(meta.Size), "reading encrypted secret")

	encryptedBuf := make([]byte, meta.Size)
	reader := io.TeeReader(io.LimitReader(sf.f, int64(meta.Size)), bar)

	_, err = io.ReadFull(reader, encryptedBuf)
	if err != nil {
		return err
	}

	plaintext, err := crypto.DecryptChaCha20Poly1305(fek[:], meta.Nonce[:], encryptedBuf)
	if err != nil {
		return err
	}

	bar2 := progressbar.DefaultBytes(int64(len(plaintext)), "writing plaintext")
	_, err = io.Copy(io.MultiWriter(w, bar2), bytes.NewReader(plaintext))
	return err
}

func (sf *SecretFile) Save() error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	payloadEnd := sf.payloadEndOffset()

	// write index table
	if _, err := sf.f.Seek(int64(payloadEnd), io.SeekStart); err != nil {
		return fmt.Errorf("seek for index table failed: %w", err)
	}

	sf.header.IndexTableOffset = payloadEnd

	err := sf.writeIndexTable()
	if err != nil {
		return err
	}

	_, err = sf.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	// set up all flags
	sf.header.CompleteFlag = FlagCompleted | FlagEncrypted | FlagCompressed

	_, err = sf.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	err = sf.writeHeader()
	if err != nil {
		return err
	}

	checksum, err := sf.calculateChecksum()
	if err != nil {
		return err
	}

	sf.header.Checksum = checksum

	_, err = sf.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	// update header
	err = sf.writeHeader()
	if err != nil {
		return err
	}

	if err := sf.f.Sync(); err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

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

	fact, err := sf.calculateChecksum()
	if err != nil {
		return err
	}

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
	fek, err := crypto.DecryptFEK(sf.masterKey[:], sf.header.EncryptedFEK, sf.header.VerificationTag)
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
