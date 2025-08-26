package helpers

import "errors"

func ConvertStringNameToBytes32(s string) ([32]byte, error) {
	if len(s) > 32 {
		return [32]byte{}, errors.New("name size must be less than 32 bytes")
	}

	res := [32]byte{}
	copy(res[:], s)

	return res, nil
}
