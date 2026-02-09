package gem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	// TagSize is the default authentication tag size in bytes.
	TagSize = 16

	// NonceSize256 is the nonce size for AES-256-GEM in bytes.
	NonceSize256 = 32

	// NonceSize128 is the nonce size for AES-128-GEM in bytes.
	NonceSize128 = 24

	bytesPerSegment uint64 = 1 << 36 // max bytes per CTR segment
	segKeyBase      uint64 = 0xFD00000000000000
)

var errAuthFailed = errors.New("gem: authentication failed")

// aesGEM implements cipher.AEAD for both AES-256-GEM and AES-128-GEM.
// The key length determines the mode (32 bytes = 256-bit, 16 = 128-bit).
type aesGEM struct {
	cipher  cipher.Block // AES cipher keyed with the original key K
	key     []byte       // raw key bytes for DeriveSubKey XOR step
	tagSize int          // tag length in bytes (4-16)
	segSize int          // override for testing; 0 = use bytesPerSegment
}

// NewAES256 creates an AES-256-GEM AEAD with a 16-byte tag.
func NewAES256(key []byte) (cipher.AEAD, error) {
	return NewAES256WithTagSize(key, TagSize)
}

// NewAES256WithTagSize creates an AES-256-GEM AEAD with a custom tag size
// (4-16 bytes).
func NewAES256WithTagSize(key []byte, tagSize int) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("gem: AES-256-GEM requires a 32-byte key")
	}
	return newGEM(key, tagSize)
}

// NewAES128 creates an AES-128-GEM AEAD with a 16-byte tag.
func NewAES128(key []byte) (cipher.AEAD, error) {
	return NewAES128WithTagSize(key, TagSize)
}

// NewAES128WithTagSize creates an AES-128-GEM AEAD with a custom tag size
// (4-16 bytes).
func NewAES128WithTagSize(key []byte, tagSize int) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, errors.New("gem: AES-128-GEM requires a 16-byte key")
	}
	return newGEM(key, tagSize)
}

func newGEM(key []byte, tagSize int) (*aesGEM, error) {
	if tagSize < 4 || tagSize > 16 {
		return nil, errors.New("gem: tag size must be 4-16 bytes")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &aesGEM{cipher: c, key: k, tagSize: tagSize}, nil
}

func (g *aesGEM) NonceSize() int { return g.headSize() + 8 }
func (g *aesGEM) Overhead() int  { return g.tagSize }

// headSize returns the nonce bytes used for subkey derivation.
func (g *aesGEM) headSize() int {
	if len(g.key) == 32 {
		return 24
	}
	return 16
}

// Seal encrypts plaintext, appends the authentication tag, and returns
// the combined ciphertext||tag. Implements cipher.AEAD.
func (g *aesGEM) Seal(
	dst, nonce, plaintext, aad []byte,
) []byte {
	if len(nonce) != g.NonceSize() {
		panic("gem: incorrect nonce length")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+g.tagSize)
	ct := out[:len(plaintext)]
	tag := out[len(plaintext):]

	copy(ct, plaintext)
	g.sealDetached(nonce, ct, aad, tag)
	return ret
}

// Open authenticates and decrypts ciphertext||tag. Implements cipher.AEAD.
func (g *aesGEM) Open(
	dst, nonce, ciphertext, aad []byte,
) ([]byte, error) {
	if len(nonce) != g.NonceSize() {
		panic("gem: incorrect nonce length")
	}
	if len(ciphertext) < g.tagSize {
		return nil, errAuthFailed
	}
	split := len(ciphertext) - g.tagSize
	ct, tag := ciphertext[:split], ciphertext[split:]

	ret, out := sliceForAppend(dst, len(ct))
	copy(out, ct)
	if err := g.openDetached(nonce, out, aad, tag); err != nil {
		for i := range out {
			out[i] = 0 // zero output on auth failure
		}
		return nil, err
	}
	return ret, nil
}

func (g *aesGEM) sealDetached(
	nonce, buf, aad, tagOut []byte,
) {
	hs := g.headSize()
	tail := nonce[hs:]
	subkey := g.deriveSubKey(nonce[:hs])
	gh := deriveGHASH(subkey, g.tagSize)
	mask := computeJ0Mask(subkey, tail)

	g.applySegmentedCTR(subkey, tail, buf)
	computeTag(g.cipher, gh, mask, aad, buf, tagOut)
}

func (g *aesGEM) openDetached(
	nonce, buf, aad, tag []byte,
) error {
	hs := g.headSize()
	tail := nonce[hs:]
	subkey := g.deriveSubKey(nonce[:hs])
	gh := deriveGHASH(subkey, g.tagSize)
	mask := computeJ0Mask(subkey, tail)

	// Verify tag over ciphertext before decrypting.
	expected := make([]byte, g.tagSize)
	computeTag(g.cipher, gh, mask, aad, buf, expected)
	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		return errAuthFailed
	}

	g.applySegmentedCTR(subkey, tail, buf)
	return nil
}

// --- Key derivation ---

func (g *aesGEM) deriveSubKey(head []byte) cipher.Block {
	if len(g.key) == 32 {
		return g.deriveSubKey256(head)
	}
	return g.deriveSubKey128(head)
}

// deriveSubKey256 implements DeriveSubKey for AES-256-GEM.
//
//	b0 = AES-CBC-MAC(K, N || "AES-256")
//	b1 = AES-CBC-MAC(K, N || "AES-GEM")
//	subkey = (b0 || b1) XOR K
func (g *aesGEM) deriveSubKey256(head []byte) cipher.Block {
	// CBC-MAC block 1: E(K, N[0:16])
	var state [blockSize]byte
	copy(state[:], head[:16])
	g.cipher.Encrypt(state[:], state[:])

	// b0 = E(K, state XOR (N[16:24] || "AES-256" || 0x80))
	var b0 [blockSize]byte
	copy(b0[:8], head[16:24])
	copy(b0[8:15], "AES-256")
	b0[15] = 0x80
	xorBlock(&b0, &state)
	g.cipher.Encrypt(b0[:], b0[:])

	// b1 = E(K, state XOR (N[16:24] || "AES-GEM" || 0x80))
	var b1 [blockSize]byte
	copy(b1[:8], head[16:24])
	copy(b1[8:15], "AES-GEM")
	b1[15] = 0x80
	xorBlock(&b1, &state)
	g.cipher.Encrypt(b1[:], b1[:])

	// subkey = (b0 || b1) XOR K
	sk := make([]byte, 32)
	copy(sk[:16], b0[:])
	copy(sk[16:], b1[:])
	xorBytes(sk, sk, g.key)

	c, _ := aes.NewCipher(sk)
	return c
}

// deriveSubKey128 implements DeriveSubKey for AES-128-GEM.
//
//	b = AES-CBC-MAC(K, N || "GEM-128")
//	subkey = b XOR K
func (g *aesGEM) deriveSubKey128(head []byte) cipher.Block {
	// CBC-MAC block 1: E(K, N[0:16])
	var state [blockSize]byte
	copy(state[:], head[:16])
	g.cipher.Encrypt(state[:], state[:])

	// b = E(K, state XOR ("GEM-128" || 0x80 || zeros))
	var block [blockSize]byte
	copy(block[:7], "GEM-128")
	block[7] = 0x80
	xorBlock(&block, &state)
	g.cipher.Encrypt(block[:], block[:])

	// subkey = b XOR K
	sk := make([]byte, 16)
	xorBytes(sk, block[:], g.key)

	c, _ := aes.NewCipher(sk)
	return c
}

// --- Segment key derivation ---

func deriveSegmentKey(
	subkey cipher.Block, tail []byte, segIdx uint32, keySize int,
) cipher.Block {
	if keySize == 32 {
		return deriveSegmentKey256(subkey, tail, segIdx)
	}
	return deriveSegmentKey128(subkey, tail, segIdx)
}

// deriveSegmentKey256 derives a 256-bit per-segment encryption key.
//
//	b0 = AES-ECB(subkey, N_tail || (segKeyBase + 2*i))
//	b1 = AES-ECB(subkey, N_tail || (segKeyBase + 2*i + 1))
//	return b0 || b1
func deriveSegmentKey256(
	subkey cipher.Block, tail []byte, segIdx uint32,
) cipher.Block {
	i := uint64(segIdx)
	var b0, b1 [blockSize]byte

	copy(b0[:8], tail)
	binary.BigEndian.PutUint64(b0[8:], segKeyBase+2*i)
	subkey.Encrypt(b0[:], b0[:])

	copy(b1[:8], tail)
	binary.BigEndian.PutUint64(b1[8:], segKeyBase+2*i+1)
	subkey.Encrypt(b1[:], b1[:])

	sk := make([]byte, 32)
	copy(sk[:16], b0[:])
	copy(sk[16:], b1[:])
	c, _ := aes.NewCipher(sk)
	return c
}

// deriveSegmentKey128 derives a 128-bit per-segment encryption key.
//
//	b = AES-ECB(subkey, N_tail || (segKeyBase + i))
func deriveSegmentKey128(
	subkey cipher.Block, tail []byte, segIdx uint32,
) cipher.Block {
	var b [blockSize]byte
	copy(b[:8], tail)
	binary.BigEndian.PutUint64(b[8:], segKeyBase+uint64(segIdx))
	subkey.Encrypt(b[:], b[:])
	c, _ := aes.NewCipher(b[:])
	return c
}

// --- GHASH key and tag mask derivation ---

// deriveGHASH derives a tag-length-specific GHASH key.
//
//	H = AES-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FEFFFFFF_FFFFFF{t})
//
// where t is the tag length in bits.
func deriveGHASH(subkey cipher.Block, tagSize int) *ghash {
	tagBits := byte(tagSize * 8)
	var h [blockSize]byte
	for i := range h {
		h[i] = 0xFF
	}
	h[8] = 0xFE
	h[15] = tagBits
	subkey.Encrypt(h[:], h[:])
	return newGHash(h)
}

// computeJ0Mask returns AES-ECB(subkey, j0) where
// j0 = N_tail || 0xFFFFFFFF_FFFFFFFE.
func computeJ0Mask(
	subkey cipher.Block, tail []byte,
) [blockSize]byte {
	var j0 [blockSize]byte
	copy(j0[:8], tail)
	for i := 8; i < 15; i++ {
		j0[i] = 0xFF
	}
	j0[15] = 0xFE
	subkey.Encrypt(j0[:], j0[:])
	return j0
}

// --- Segmented CTR mode ---

// applySegmentedCTR encrypts/decrypts buf using AES-CTR32 with per-segment
// re-keying. Each segment is at most bytesPerSegment bytes (2^36).
func (g *aesGEM) applySegmentedCTR(
	subkey cipher.Block, tail, buf []byte,
) {
	maxSeg := bytesPerSegment
	if g.segSize > 0 {
		maxSeg = uint64(g.segSize)
	}
	offset := 0
	segIdx := uint32(0)

	for offset < len(buf) {
		segKey := deriveSegmentKey(
			subkey, tail, segIdx, len(g.key),
		)
		// IV: N_tail(8) || segment_index(4) || 0x00000000(4)
		var iv [blockSize]byte
		copy(iv[:8], tail)
		binary.BigEndian.PutUint32(iv[8:12], segIdx)

		remaining := uint64(len(buf) - offset)
		segLen := remaining
		if segLen > maxSeg {
			segLen = maxSeg
		}
		ctr32XOR(segKey, iv, buf[offset:offset+int(segLen)])

		offset += int(segLen)
		segIdx++
	}
}

// ctr32XOR applies AES-CTR with a 32-bit big-endian counter (last 4 bytes
// of the 16-byte IV). Go's crypto/cipher.NewCTR increments the full block,
// so we implement 32-bit CTR manually.
func ctr32XOR(
	block cipher.Block, iv [blockSize]byte, data []byte,
) {
	var counter [blockSize]byte
	copy(counter[:], iv[:])
	var ks [blockSize]byte

	for len(data) > 0 {
		block.Encrypt(ks[:], counter[:])
		n := blockSize
		if len(data) < n {
			n = len(data)
		}
		xorBytes(data[:n], data[:n], ks[:n])
		data = data[n:]

		// Increment only the last 4 bytes.
		c := binary.BigEndian.Uint32(counter[12:])
		c++
		binary.BigEndian.PutUint32(counter[12:], c)
	}
}

// --- Authentication tag ---

// computeTag computes the GEM authentication tag:
//
//	S  = GHASH(H, aad || pad || ct || pad || len(aad) || len(ct))
//	S2 = AES-ECB(K, S)           -- uses original key, not subkey
//	T  = MSB_t(tagMask XOR S2)
func computeTag(
	origKey cipher.Block,
	gh *ghash,
	mask [blockSize]byte,
	aad, ct, tagOut []byte,
) {
	gh.updatePadded(aad)
	gh.updatePadded(ct)

	var lenBlock [blockSize]byte
	binary.BigEndian.PutUint64(lenBlock[:8], uint64(len(aad))*8)
	binary.BigEndian.PutUint64(lenBlock[8:], uint64(len(ct))*8)
	gh.update(lenBlock)

	s := gh.finalize()
	origKey.Encrypt(s[:], s[:]) // S2 = E(K, S)
	xorBlock(&s, &mask)        // T = tagMask XOR S2
	copy(tagOut, s[:])          // MSB_t (first tagSize bytes)
}

// --- Helpers ---

func xorBlock(dst, src *[blockSize]byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func xorBytes(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

// sliceForAppend extends dst by n bytes, reusing capacity when possible.
// Follows the same pattern as Go's crypto/cipher/gcm.go.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
