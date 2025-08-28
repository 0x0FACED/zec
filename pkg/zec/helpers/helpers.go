package helpers

import (
	"errors"
	"strings"
)

func ConvertStringNameToBytes32(s string) ([32]byte, error) {
	if len(s) > 32 {
		return [32]byte{}, errors.New("name size must be less than 32 bytes")
	}

	res := [32]byte{}
	copy(res[:], s)

	return res, nil
}

func Bytes32ToString(b [32]byte) string {
	end := len(b)
	for i, v := range b {
		if v == 0 {
			end = i
			break
		}
	}
	return strings.TrimSpace(string(b[:end]))
}
