package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMAC calculates Verification Tag from master key.
// Verification Tag used to verify password provided by user.
func HMAC(masterKey [32]byte, headerPayload []byte) [16]byte {
	// calculate verification tag
	h := hmac.New(sha256.New, masterKey[:])

	_, _ = h.Write([]byte(ZecVerification)) // as magic
	_, _ = h.Write(headerPayload)
	fullTag := h.Sum(nil)

	var verificationTag [16]byte
	copy(verificationTag[:], fullTag[:VerificationTagSize])

	return verificationTag
}
