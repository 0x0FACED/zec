package types

type SecretData struct {
	Meta SecretMeta // not written as secret
	Val  []byte     // secret data (must be excrypted + zipped, but not now)
}
