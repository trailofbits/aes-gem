// Package gem implements AES-GEM (Galois Extended Mode), an AEAD cipher
// with extended nonces and hierarchical key derivation.
//
// GHASH is implemented here because Go's standard library only exposes
// it internally (crypto/internal/fips140/gcm). There is no public
// GHASH API in crypto/cipher or golang.org/x/crypto.
package gem

const blockSize = 16

// ghash implements GHASH: a universal hash over GF(2^128).
type ghash struct {
	h     [blockSize]byte // GHASH key
	state [blockSize]byte // running accumulator
}

func newGHash(h [blockSize]byte) *ghash {
	return &ghash{h: h}
}

// update XORs a full 16-byte block into the state and multiplies by H.
func (g *ghash) update(block [blockSize]byte) {
	for i := range g.state {
		g.state[i] ^= block[i]
	}
	g.state = gfMul(&g.state, &g.h)
}

// updatePadded processes arbitrary-length data, zero-padding the final
// partial block if necessary (matching GCM's GHASH padding).
func (g *ghash) updatePadded(data []byte) {
	for len(data) >= blockSize {
		var block [blockSize]byte
		copy(block[:], data[:blockSize])
		g.update(block)
		data = data[blockSize:]
	}
	if len(data) > 0 {
		var block [blockSize]byte
		copy(block[:], data)
		g.update(block)
	}
}

// finalize returns the current GHASH state.
func (g *ghash) finalize() [blockSize]byte {
	return g.state
}

// gfMul multiplies two elements in GF(2^128) using the NIST SP 800-38D
// bit ordering (MSB of first byte = x^0).
//
// Constant-time: all branches are replaced with masked operations so
// that the execution path is independent of secret data.
func gfMul(x, y *[blockSize]byte) [blockSize]byte {
	var z [blockSize]byte // accumulator
	var v [blockSize]byte // shifted multiplicand
	copy(v[:], y[:])

	for i := 0; i < 128; i++ {
		// Extract bit i of x (MSB-first within each byte) as 0 or 1,
		// then expand to a full-byte mask (0x00 or 0xFF).
		bit := (x[i/8] >> uint(7-i%8)) & 1
		mask := byte(0) - bit
		for j := range z {
			z[j] ^= v[j] & mask
		}

		// Save bit 127 of v (LSB of last byte), expand to mask.
		carry := v[15] & 1
		carryMask := byte(0) - carry

		// Right-shift v by 1 bit.
		for j := 15; j > 0; j-- {
			v[j] = (v[j] >> 1) | (v[j-1] << 7)
		}
		v[0] >>= 1

		// Conditionally XOR the reduction polynomial
		// R = 0xE1 || 0^120.
		v[0] ^= 0xE1 & carryMask
	}
	return z
}
