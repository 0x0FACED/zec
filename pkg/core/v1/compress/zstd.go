package compress

import (
	"bytes"
	"io"

	"github.com/klauspost/compress/zstd"
)

// CompressZSTD compresses input data using zstd
func CompressZSTD(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	// default settings
	encoder, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}

	_, err = encoder.Write(data)
	if err != nil {
		return nil, err
	}

	err = encoder.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecompressZSTD decompresses zstd-compressed data
func DecompressZSTD(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	var out bytes.Buffer

	_, err = io.Copy(&out, decoder)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}
