package inventory

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// VerifyDigest recomputes a digest over bytes for the checksum algorithms worth
// verifying.
//
// The TEA enum also names MD5, SHA-1 and the BLAKE families. The first two
// prove nothing about integrity against a motivated party and the last are not
// in the standard library, so an unrecognised algorithm reports "not checked"
// rather than a failure — the alternative would be to claim verification the
// suite did not perform.
func VerifyDigest(algType string, body []byte) (string, bool) {
	var h hash.Hash
	switch strings.ToUpper(strings.ReplaceAll(algType, "-", "_")) {
	case "SHA_256", "SHA256":
		h = sha256.New()
	case "SHA_384", "SHA384":
		h = sha512.New384()
	case "SHA_512", "SHA512":
		h = sha512.New()
	default:
		return "", false
	}
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), true
}

// ChecksumMismatch verifies the digests published for a format against the
// bytes actually served, and describes the first mismatch it finds.
//
// A mismatch is the check that catches a stale download URL. A TEA artifact
// revision is immutable by design, so if the bytes behind it changed, every
// consumer that verifies the published digest will reject a document the API is
// still advertising as current.
func (f Format) ChecksumMismatch(body []byte) string {
	for _, ck := range f.Checksums {
		got, checked := VerifyDigest(ck.AlgType, body)
		if !checked {
			continue
		}
		if !strings.EqualFold(got, ck.AlgValue) {
			return fmt.Sprintf("the published %s checksum does not match the bytes served: "+
				"TEA says %s, the download is %s", ck.AlgType, shortDigest(ck.AlgValue), shortDigest(got))
		}
	}
	return ""
}

func shortDigest(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}
