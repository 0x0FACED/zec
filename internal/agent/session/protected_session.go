package session

import (
	"os"
	"time"

	"github.com/0x0FACED/zec/pkg/zec"
	"github.com/awnumar/memguard"
)

type ProtectedSession struct {
	fek           *memguard.Enclave
	masterKey     *memguard.Enclave
	f             *os.File
	header        *zec.Header
	containerPath string
	userID        string
	createdAt     time.Time
	expiresAt     time.Time
	lastAccess    time.Time
}

func NewProtectedSession(pass []byte, path string, f *os.File, header *zec.Header, userID string) (*ProtectedSession, error) {
	masterKey := zec.DeriveKey(pass, header.ArgonSalt, header.ArgonMemoryLog2,
		header.ArgonIterations, header.ArgonParallelism)

	fek, err := zec.DecryptFEK(masterKey, header.EncryptedFEK,
		header.VerificationTag, header.AuthenticatedBytes())
	if err != nil {
		return nil, err
	}

	return &ProtectedSession{
		fek:           memguard.NewEnclave(fek[:]),
		masterKey:     memguard.NewEnclave(masterKey[:]),
		f:             f,
		header:        header,
		containerPath: path,
		userID:        userID,
		createdAt:     time.Now(),
		expiresAt:     time.Now().Add(15 * time.Minute), // временно, должны передавать из вне
		lastAccess:    time.Now(),
	}, nil
}

func (ps *ProtectedSession) FEK() ([]byte, error) {
	buf, err := ps.fek.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()

	data := make([]byte, buf.Size())
	copy(data, buf.Bytes())

	return data, nil
}

func (ps *ProtectedSession) MasterKey() ([]byte, error) {
	buf, err := ps.masterKey.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()

	data := make([]byte, buf.Size())
	copy(data, buf.Bytes())

	return data, nil
}

func (ps *ProtectedSession) Close() error {
	return ps.f.Close()
}
