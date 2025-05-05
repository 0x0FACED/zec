package types_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/0x0FACED/zec/pkg/core/v1/file"
	"github.com/0x0FACED/zec/pkg/core/v1/types"
	"github.com/stretchr/testify/assert"
)

// helper func that deletes created file
func removeFile(t *testing.T, filename string) {
	t.Helper()

	err := os.Remove(filename)

	assert.NoError(t, err)
}

func createFile(t *testing.T, filename string) (*types.SecretFile, error) {
	t.Helper()

	sf, err := types.NewSecretFile(filename)
	assert.NoError(t, err)

	assert.NotNil(t, sf)
	assert.NotNil(t, sf.Header())

	// current version is 1
	assert.Equal(t, uint8(1), sf.Header().Version)

	return sf, nil
}

// TestFile_NewSecretFile tests creating new file by provided filename
// TODO: add more assertions
func TestFile_NewSecretFile(t *testing.T) {
	filename := "test-file.zec"

	_, _ = createFile(t, filename)
	defer removeFile(t, filename)
}

// TestFile_WriteSecret tests
func TestFile_WriteSecret(t *testing.T) {
	filename := "test-file.zec"

	sf, _ := createFile(t, filename)
	defer removeFile(t, filename)

	testPayload1 := "test-payload-1"

	testMeta, err := types.NewSecretMeta("test-name-1", uint64(len(testPayload1)))
	assert.NoError(t, err)

	testPayload1Bytes := make([]byte, len(testPayload1))
	buf := bytes.NewBuffer(testPayload1Bytes)
	err = sf.WriteSecret(testMeta, buf)
	assert.NoError(t, err)

	assert.Equal(t, uint64(len(testPayload1)), sf.Header().DataSize)

	// save closes file
	err = sf.Save()
	assert.NoError(t, err)

	assert.Equal(t, uint64(len(testPayload1)), sf.IndexTable().Secrets[0].Size)
}

// func TestFile_AddMultipleSecrets(t *testing.T) {
// 	filename := "multi-secrets.zec"
// 	sf, _ := createFile(t, filename)
// 	defer removeFile(t, filename)

// 	payloads := []string{"payload1", "payload2", "payload3"}
// 	for i, data := range payloads {
// 		meta, err := types.NewSecretMeta("secret-"+string('A'+i), uint64(len(data)))
// 		assert.NoError(t, err)
// 		err = sf.WriteSecret(meta, bytes.NewBuffer([]byte(data)))
// 		assert.NoError(t, err)
// 	}

// 	err := sf.Save()
// 	assert.NoError(t, err)
// 	assert.Equal(t, len(payloads), len(sf.IndexTable().Secrets))
// }

func TestFile_ReopenAndReadSecrets(t *testing.T) {
	filename := "read-after-reopen.zec"
	sf, _ := createFile(t, filename)
	defer removeFile(t, filename)

	data := "super-secret"
	meta, err := types.NewSecretMeta("secret", uint64(len(data)))
	assert.NoError(t, err)

	err = sf.WriteSecret(meta, bytes.NewBuffer([]byte(data)))
	assert.NoError(t, err)

	err = sf.Save()
	assert.NoError(t, err)

	sf2, err := file.Open(filename)
	assert.NoError(t, err)
	assert.NotNil(t, sf2)

	assert.Equal(t, uint64(len(data)), sf2.IndexTable().Secrets[0].Size)

	readData, err := sf2.ReadSecret("secret")
	assert.NoError(t, err)
	assert.Equal(t, data, string(readData.Val))
}

func TestFile_AppendToExistingFile(t *testing.T) {
	filename := "append.zec"
	sf, _ := createFile(t, filename)
	defer removeFile(t, filename)

	meta1, _ := types.NewSecretMeta("alpha", 4)
	_ = sf.WriteSecret(meta1, bytes.NewBuffer([]byte("1234")))
	_ = sf.Save()

	// reopen
	sf2, err := file.Open(filename)
	assert.NoError(t, err)

	meta2, _ := types.NewSecretMeta("beta", 3)
	_ = sf2.WriteSecret(meta2, bytes.NewBuffer([]byte("abc")))
	_ = sf2.Save()

	sf3, err := file.Open(filename)
	assert.NoError(t, err)

	assert.Equal(t, 2, len(sf3.IndexTable().Secrets))

	readData1, err := sf3.ReadSecret("alpha")
	assert.NoError(t, err)
	assert.Equal(t, "1234", string(readData1.Val))

	readData2, err := sf3.ReadSecret("beta")
	assert.NoError(t, err)
	assert.Equal(t, "abc", string(readData2.Val))
}

func TestFile_EmptyFileHandling(t *testing.T) {
	filename := "empty.zec"
	sf, _ := createFile(t, filename)
	defer removeFile(t, filename)

	assert.Equal(t, 0, len(sf.IndexTable().Secrets))
	assert.Equal(t, uint64(0), sf.Header().DataSize)

	err := sf.Save()
	assert.NoError(t, err)

	sf2, err := file.Open(filename)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(sf2.IndexTable().Secrets))
}
