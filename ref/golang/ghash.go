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
// This is a simple schoolbook implementation for clarity, not constant-time.
func gfMul(x, y *[blockSize]byte) [blockSize]byte {
	var z [blockSize]byte // accumulator
	var v [blockSize]byte // shifted multiplicand
	copy(v[:], y[:])

	for i := 0; i < 128; i++ {
		// If bit i of x is set (MSB-first within each byte)
		if x[i/8]&(0x80>>uint(i%8)) != 0 {
			for j := range z {
				z[j] ^= v[j]
			}
		}

		// Save bit 127 of v (LSB of last byte)
		carry := v[15] & 1

		// Right-shift v by 1 bit
		for j := 15; j > 0; j-- {
			v[j] = (v[j] >> 1) | (v[j-1] << 7)
		}
		v[0] >>= 1

		// If the shifted-out bit was 1, XOR with the reduction
		// polynomial R = 0xE1 || 0^120.
		if carry != 0 {
			v[0] ^= 0xE1
		}
	}
	return z
}
