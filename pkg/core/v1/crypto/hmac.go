package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMAC calculates Verification Tag from master key.
// Verification Tag used to verify password provided by user.
func HMAC(masterKey [32]byte) [16]byte {
	// calculate verification tag
	h := hmac.New(sha256.New, masterKey[:])

	_, _ = h.Write([]byte(ZecVerification))
	fullTag := h.Sum(nil)

	var verificationTag [16]byte
	copy(verificationTag[:], fullTag[:VerificationTagSize])

	return verificationTag
}
