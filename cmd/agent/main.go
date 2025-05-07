package main

import (
	"bytes"
	"fmt"

	"github.com/0x0FACED/zec/pkg/core/v1/file"
	"github.com/0x0FACED/zec/pkg/core/v1/types"
)

// TEMP CODE
// In the future it will be agent that manages sessions
func main() {
	// TEST

	password := "test-password"
	testSecretPayload1 := "some payload1"
	name1 := "test1"
	testSecretPayload2 := "some payload2"
	name2 := "test2"
	testSecretPayload3 := "some payload3"
	name3 := "test3"

	name1Bytes := [16]byte{}
	copy(name1Bytes[:], name1)
	name2Bytes := [16]byte{}
	copy(name2Bytes[:], name2)
	name3Bytes := [16]byte{}
	copy(name3Bytes[:], name3)

	testSecretMeta1, _ := types.NewSecretMeta(name1, uint64(len(testSecretPayload1)))

	testSecretMeta2, _ := types.NewSecretMeta(name2, uint64(len(testSecretPayload2)))

	testSecretMeta3, _ := types.NewSecretMeta(name3, uint64(len(testSecretPayload3)))

	secretFile, err := types.NewSecretFile("test_multiple.zec", []byte(password))
	if err != nil {
		panic(err)
	}

	buf := bytes.NewBuffer([]byte(testSecretPayload1))
	err = secretFile.WriteSecret(testSecretMeta1, buf)
	if err != nil {
		panic(err)
	}

	buf2 := bytes.NewBuffer([]byte(testSecretPayload2))
	err = secretFile.WriteSecret(testSecretMeta2, buf2)
	if err != nil {
		panic(err)
	}

	buf3 := bytes.NewBuffer([]byte(testSecretPayload3))
	err = secretFile.WriteSecret(testSecretMeta3, buf3)
	if err != nil {
		panic(err)
	}

	err = secretFile.Save()
	if err != nil {
		panic(err)
	}

	fmt.Println("Saved")

	sf, err := file.Open("test_multiple.zec", []byte(password))
	if err != nil {
		panic(err)
	}
	defer sf.Close()

	fmt.Println("Offset of index table:", sf.Header().IndexTableOffset)

	err = sf.ValidateChecksum()
	if err != nil {
		panic(err)
	}

	fmt.Println("Header:", sf.Header().Version)
	fmt.Println("IndexTable:", sf.IndexTable())

	secrets, err := file.ReadAllSecretsFromIndex(sf.File(), sf.IndexTable())
	if err != nil {
		panic(err)
	}

	fmt.Println("Secrets 1:")
	for i := range len(secrets) {
		secret, err := sf.ReadSecret(string(secrets[i].Meta.ID[:]))
		if err != nil {
			panic(err)
		}
		_ = secret
		fmt.Printf("Secret #%d, payload: %s, offset: %d\n", i, secrets[i].Val, secrets[i].Meta.Offset)
	}

	// trying get secret by name
	data1, err := sf.ReadSecret(name1)
	if err != nil {
		panic(err)
	}

	fmt.Println("secret data 1:", string(data1.Val))

	// WRITE ANOTHER SECRETS

	testSecretPayload4 := "some payload4"
	name4 := "test4"
	testSecretPayload5 := "some payload5"
	name5 := "test5"
	testSecretPayload6 := "some payload6"
	name6 := "test6"

	name4Bytes := [16]byte{}
	copy(name4Bytes[:], name4)
	name5Bytes := [16]byte{}
	copy(name5Bytes[:], name5)
	name6Bytes := [16]byte{}
	copy(name6Bytes[:], name6)

	testSecretMeta4, _ := types.NewSecretMeta(name4, uint64(len(testSecretPayload4)))

	testSecretMeta5, _ := types.NewSecretMeta(name5, uint64(len(testSecretPayload5)))

	testSecretMeta6, _ := types.NewSecretMeta(name6, uint64(len(testSecretPayload6)))

	err = sf.WriteSecret(testSecretMeta4, bytes.NewBuffer([]byte(testSecretPayload4)))
	if err != nil {
		panic(err)
	}

	err = sf.WriteSecret(testSecretMeta5, bytes.NewBuffer([]byte(testSecretPayload4)))
	if err != nil {
		panic(err)
	}

	err = sf.WriteSecret(testSecretMeta6, bytes.NewBuffer([]byte(testSecretPayload4)))
	if err != nil {
		panic(err)
	}

	// trying get secret by name
	data1, err = sf.ReadSecret(name6)
	if err != nil {
		panic(err)
	}

	fmt.Println("secret data 6:", string(data1.Val))

	secrets, err = file.ReadAllSecretsFromIndex(sf.File(), sf.IndexTable())
	if err != nil {
		panic(err)
	}

	fmt.Println("Secrets 2:")
	for i := range len(secrets) {
		secret, err := sf.ReadSecret(string(secrets[i].Meta.ID[:]))
		if err != nil {
			panic(err)
		}
		fmt.Printf("Secret #%d, payload: %s, offset: %d\n", i, secret.Val, secret.Meta.Offset)
	}

	err = sf.Save()
	if err != nil {
		panic(err)
	}
}
