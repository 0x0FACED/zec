package main

import (
	"bytes"
	"fmt"

	"github.com/0x0FACED/zec/pkg/core/v1/file"
	"github.com/0x0FACED/zec/pkg/core/v1/types"
	"github.com/google/uuid"
)

func main() {
	// TEST

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

	secretFile, err := types.NewSecretFile("test_multiple.zec", uuid.New())
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

	sf, err := file.Open("test_multiple.zec")
	if err != nil {
		panic(err)
	}
	defer sf.Close()

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

	fmt.Println("Secrets:")
	for i, secret := range secrets {
		fmt.Printf("Secret #%d, payload: %s\n", i, secret.Val)
	}

	// trying get secret by name
	data1, err := sf.ReadSecret(name1)
	if err != nil {
		panic(err)
	}

	fmt.Println("secret data:", string(data1.Val))
}
