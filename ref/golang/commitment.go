package gem

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// KeyCommitment256 computes a 256-bit key commitment for AES-256-GEM.
//
//	subkey = DeriveSubKey(K, N[0:24])
//	Q = AES-CTR32(subkey, N[24:32] || 0xFFFFFFFF_FFFFFFFC, zeros(32))
func KeyCommitment256(key, nonce []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != NonceSize256 {
		return nil, errors.New("gem: invalid key or nonce size")
	}
	return keyCommitment(key, nonce, 24)
}

// KeyCommitment128 computes a 256-bit key commitment for AES-128-GEM.
//
//	subkey = DeriveSubKey(K, N[0:16])
//	Q = AES-CTR32(subkey, N[16:24] || 0xFFFFFFFF_FFFFFFFC, zeros(32))
func KeyCommitment128(key, nonce []byte) ([]byte, error) {
	if len(key) != 16 || len(nonce) != NonceSize128 {
		return nil, errors.New("gem: invalid key or nonce size")
	}
	return keyCommitment(key, nonce, 16)
}

func keyCommitment(
	key, nonce []byte, headSize int,
) ([]byte, error) {
	g, err := newGEM(key, TagSize)
	if err != nil {
		return nil, err
	}
	tail := nonce[headSize:]
	subkey := g.deriveSubKey(nonce[:headSize])

	var iv [blockSize]byte
	copy(iv[:8], tail)
	binary.BigEndian.PutUint64(iv[8:], 0xFFFFFFFFFFFFFFFC)

	q := make([]byte, 32)
	ctr32XOR(subkey, iv, q)
	return q, nil
}

// VerifyKeyCommitment256 verifies a key commitment for AES-256-GEM
// in constant time.
func VerifyKeyCommitment256(
	key, nonce, commitment []byte,
) (bool, error) {
	expected, err := KeyCommitment256(key, nonce)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, commitment) == 1, nil
}

// VerifyKeyCommitment128 verifies a key commitment for AES-128-GEM
// in constant time.
func VerifyKeyCommitment128(
	key, nonce, commitment []byte,
) (bool, error) {
	expected, err := KeyCommitment128(key, nonce)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, commitment) == 1, nil
}
