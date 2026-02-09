package gem

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestAES256RoundTrip(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	aead, err := NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}

	pt := []byte("hello, AES-256-GEM!")
	aad := []byte("additional data")

	ct := aead.Seal(nil, nonce, pt, aad)
	got, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch: got %x, want %x", got, pt)
	}
}

func TestAES128RoundTrip(t *testing.T) {
	key := randBytes(t, 16)
	nonce := randBytes(t, NonceSize128)

	aead, err := NewAES128(key)
	if err != nil {
		t.Fatal(err)
	}

	pt := []byte("hello, AES-128-GEM!")
	aad := []byte("additional data")

	ct := aead.Seal(nil, nonce, pt, aad)
	got, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch: got %x, want %x", got, pt)
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	aead, err := NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := aead.Seal(nil, nonce, nil, []byte("aad-only"))
	got, err := aead.Open(nil, nonce, ct, []byte("aad-only"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestAuthFailureBitFlip(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	aead, err := NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := aead.Seal(nil, nonce, []byte("test"), nil)
	ct[0] ^= 0x01 // flip one bit of ciphertext

	_, err = aead.Open(nil, nonce, ct, nil)
	if err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestAuthFailureWrongAAD(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	aead, err := NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := aead.Seal(nil, nonce, []byte("test"), []byte("aad1"))
	_, err = aead.Open(nil, nonce, ct, []byte("aad2"))
	if err == nil {
		t.Fatal("expected authentication failure with wrong AAD")
	}
}

func TestAuthFailureWrongKey(t *testing.T) {
	key1 := randBytes(t, 32)
	key2 := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	aead1, _ := NewAES256(key1)
	aead2, _ := NewAES256(key2)

	ct := aead1.Seal(nil, nonce, []byte("secret"), nil)
	_, err := aead2.Open(nil, nonce, ct, nil)
	if err == nil {
		t.Fatal("expected authentication failure with wrong key")
	}
}

func TestCustomTagSize(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	for _, ts := range []int{4, 8, 12, 16} {
		aead, err := NewAES256WithTagSize(key, ts)
		if err != nil {
			t.Fatal(err)
		}
		if aead.Overhead() != ts {
			t.Fatalf("overhead = %d, want %d", aead.Overhead(), ts)
		}
		pt := []byte("tag size test")
		ct := aead.Seal(nil, nonce, pt, nil)
		if len(ct) != len(pt)+ts {
			t.Fatalf("ct len = %d, want %d", len(ct), len(pt)+ts)
		}
		got, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			t.Fatalf("tagSize=%d: decrypt failed: %v", ts, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("plaintext mismatch")
		}
	}
}

func TestTagSizeDomainSeparation(t *testing.T) {
	// Encrypting the same plaintext with different tag sizes must produce
	// different ciphertexts (because H differs).
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)
	pt := []byte("domain separation test")

	aead12, _ := NewAES256WithTagSize(key, 12)
	aead16, _ := NewAES256WithTagSize(key, 16)

	ct12 := aead12.Seal(nil, nonce, pt, nil)
	ct16 := aead16.Seal(nil, nonce, pt, nil)

	// The ciphertext bodies should differ because H differs,
	// which means the tag mask XOR chain differs. Actually, the
	// ciphertext bytes are identical (CTR doesn't depend on tag size),
	// but the tags must differ.
	tag12 := ct12[len(pt):]
	tag16 := ct16[len(pt):]
	if bytes.Equal(tag12, tag16[:12]) {
		t.Fatal("tags should differ due to domain separation")
	}
}

func TestMultiSegment(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	g, err := newGEM(key, TagSize)
	if err != nil {
		t.Fatal(err)
	}
	g.segSize = 64 // 64 bytes per segment for testing

	pt := randBytes(t, 200) // ~3 segments
	aad := []byte("multi-segment aad")

	ct := g.Seal(nil, nonce, pt, aad)
	got, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("multi-segment decrypt failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("multi-segment plaintext mismatch")
	}
}

func TestMultiSegmentAuthFailure(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	g, err := newGEM(key, TagSize)
	if err != nil {
		t.Fatal(err)
	}
	g.segSize = 64

	pt := randBytes(t, 200)
	ct := g.Seal(nil, nonce, pt, nil)

	// Flip a bit in the middle of a later segment.
	ct[100] ^= 0x01

	g2, _ := newGEM(key, TagSize)
	g2.segSize = 64
	_, err = g2.Open(nil, nonce, ct, nil)
	if err == nil {
		t.Fatal("expected auth failure on modified multi-segment data")
	}
}

func TestKeyCommitment256(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	q, err := KeyCommitment256(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 32 {
		t.Fatalf("commitment length = %d, want 32", len(q))
	}

	ok, err := VerifyKeyCommitment256(key, nonce, q)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("commitment verification failed")
	}

	// Wrong key must not verify.
	wrongKey := randBytes(t, 32)
	ok, _ = VerifyKeyCommitment256(wrongKey, nonce, q)
	if ok {
		t.Fatal("commitment verified with wrong key")
	}
}

func TestKeyCommitment128(t *testing.T) {
	key := randBytes(t, 16)
	nonce := randBytes(t, NonceSize128)

	q, err := KeyCommitment128(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyKeyCommitment128(key, nonce, q)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("commitment verification failed")
	}
}

func TestLargeMessage(t *testing.T) {
	key := randBytes(t, 32)
	nonce := randBytes(t, NonceSize256)

	aead, _ := NewAES256(key)
	pt := randBytes(t, 1<<16) // 64 KiB

	ct := aead.Seal(nil, nonce, pt, nil)
	got, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("large message mismatch")
	}
}

func TestGFMulIdentity(t *testing.T) {
	// In GF(2^128) with NIST bit ordering, the multiplicative identity
	// is 0x80000000... (bit 0 set = MSB of first byte).
	var identity [16]byte
	identity[0] = 0x80

	var x [16]byte
	x[0] = 0x12
	x[1] = 0x34
	x[5] = 0xAB

	result := gfMul(&identity, &x)
	if result != x {
		t.Fatalf("gfMul(1, x) != x\ngot:  %x\nwant: %x", result, x)
	}
}

func TestGFMulZero(t *testing.T) {
	var zero [16]byte
	var x [16]byte
	x[0] = 0xFF
	x[15] = 0x42

	result := gfMul(&zero, &x)
	if result != zero {
		t.Fatalf("gfMul(0, x) != 0: got %x", result)
	}

	result = gfMul(&x, &zero)
	if result != zero {
		t.Fatalf("gfMul(x, 0) != 0: got %x", result)
	}
}

func TestGFMulCommutative(t *testing.T) {
	var a, b [16]byte
	a[0] = 0x53
	a[7] = 0xAC
	b[3] = 0xDE
	b[15] = 0x01

	ab := gfMul(&a, &b)
	ba := gfMul(&b, &a)
	if ab != ba {
		t.Fatalf("gfMul not commutative:\na*b = %x\nb*a = %x", ab, ba)
	}
}

// --- Mutation testing coverage additions ---

func TestGFMulKnownValues(t *testing.T) {
	// Pre-computed GF(2^128) multiplication results using NIST bit
	// ordering. These exercise carry/reduction, multi-byte XOR
	// accumulation, and the shift chain in gfMul.
	tests := []struct {
		name     string
		x, y     [16]byte
		expected string // hex
	}{
		{
			name: "NIST-H-times-block",
			x: [16]byte{
				0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
				0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
			},
			y: [16]byte{
				0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
				0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
			},
			expected: "5e2ec746917062882c85b0685353deb7",
		},
		{
			name: "sparse-with-reduction",
			x: [16]byte{
				0xAC, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			y: [16]byte{
				0x5B, 0x00, 0x00, 0xDE, 0x00, 0x00, 0x00, 0x00,
				0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83,
			},
			expected: "760e05ecfd58bd5541e4409400000187",
		},
		{
			name: "all-ones-times-pattern",
			x: [16]byte{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			y: [16]byte{
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
			},
			expected: "0083ffffffffffffffffffffffffffbe",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := gfMul(&tc.x, &tc.y)
			got := hex.EncodeToString(result[:])
			if got != tc.expected {
				t.Fatalf("got %s, want %s", got, tc.expected)
			}
		})
	}
}

func TestInputValidation(t *testing.T) {
	// Wrong key sizes.
	if _, err := NewAES256(make([]byte, 16)); err == nil {
		t.Fatal("NewAES256 accepted 16-byte key")
	}
	if _, err := NewAES256(make([]byte, 31)); err == nil {
		t.Fatal("NewAES256 accepted 31-byte key")
	}
	if _, err := NewAES256(make([]byte, 33)); err == nil {
		t.Fatal("NewAES256 accepted 33-byte key")
	}
	if _, err := NewAES128(make([]byte, 32)); err == nil {
		t.Fatal("NewAES128 accepted 32-byte key")
	}
	if _, err := NewAES128(make([]byte, 15)); err == nil {
		t.Fatal("NewAES128 accepted 15-byte key")
	}
	if _, err := NewAES128(make([]byte, 17)); err == nil {
		t.Fatal("NewAES128 accepted 17-byte key")
	}

	// Tag size boundaries.
	if _, err := NewAES256WithTagSize(make([]byte, 32), 3); err == nil {
		t.Fatal("accepted tag size 3")
	}
	if _, err := NewAES256WithTagSize(make([]byte, 32), 17); err == nil {
		t.Fatal("accepted tag size 17")
	}
	if _, err := NewAES256WithTagSize(make([]byte, 32), 0); err == nil {
		t.Fatal("accepted tag size 0")
	}

	// Valid boundaries must succeed.
	if _, err := NewAES256WithTagSize(make([]byte, 32), 4); err != nil {
		t.Fatalf("rejected valid tag size 4: %v", err)
	}
	if _, err := NewAES256WithTagSize(make([]byte, 32), 16); err != nil {
		t.Fatalf("rejected valid tag size 16: %v", err)
	}
}

func TestKeyCommitmentValidation(t *testing.T) {
	if _, err := KeyCommitment256(make([]byte, 16), make([]byte, 32)); err == nil {
		t.Fatal("KC256 accepted 16-byte key")
	}
	if _, err := KeyCommitment256(make([]byte, 32), make([]byte, 24)); err == nil {
		t.Fatal("KC256 accepted 24-byte nonce")
	}
	if _, err := KeyCommitment128(make([]byte, 32), make([]byte, 24)); err == nil {
		t.Fatal("KC128 accepted 32-byte key")
	}
	if _, err := KeyCommitment128(make([]byte, 16), make([]byte, 32)); err == nil {
		t.Fatal("KC128 accepted 32-byte nonce")
	}
}

func TestCiphertextTooShort(t *testing.T) {
	aead, _ := NewAES256(make([]byte, 32))

	if _, err := aead.Open(nil, make([]byte, NonceSize256), nil, nil); err == nil {
		t.Fatal("accepted nil ciphertext")
	}
	if _, err := aead.Open(nil, make([]byte, NonceSize256), make([]byte, 15), nil); err == nil {
		t.Fatal("accepted 15-byte ciphertext (shorter than tag)")
	}
}

func TestAES128KnownVector(t *testing.T) {
	// Deterministic AES-128-GEM vectors with all-zero key and nonce.
	key := make([]byte, 16)
	nonce := make([]byte, NonceSize128)
	aead, _ := NewAES128(key)

	// Empty plaintext, empty AAD.
	ct1 := aead.Seal(nil, nonce, nil, nil)
	if got := hex.EncodeToString(ct1); got != "56f753929ea237cbeee33ce798bd4325" {
		t.Fatalf("empty/empty tag: got %s", got)
	}

	// With plaintext, empty AAD.
	pt := []byte("hello, AES-128-GEM!")
	ct2 := aead.Seal(nil, nonce, pt, nil)
	split := len(ct2) - TagSize
	if got := hex.EncodeToString(ct2[:split]); got != "b6d5047492f37c7182862ef6bb3e432edab41b" {
		t.Fatalf("pt/empty ct: got %s", got)
	}
	if got := hex.EncodeToString(ct2[split:]); got != "38ae7a08458b58aef20831517a44a526" {
		t.Fatalf("pt/empty tag: got %s", got)
	}

	// With plaintext and AAD.
	aad := []byte("additional data")
	ct3 := aead.Seal(nil, nonce, pt, aad)
	split = len(ct3) - TagSize
	if got := hex.EncodeToString(ct3[split:]); got != "6d793481b57d3331a38e2c5daa3b8c10" {
		t.Fatalf("pt/aad tag: got %s", got)
	}

	// Verify decryption.
	got, err := aead.Open(nil, nonce, ct3, aad)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("plaintext mismatch")
	}
}

func TestAES128AuthFailure(t *testing.T) {
	key := make([]byte, 16)
	key[0] = 0x42
	nonce := make([]byte, NonceSize128)
	aead, _ := NewAES128(key)

	// Bit flip.
	ct := aead.Seal(nil, nonce, []byte("test128"), []byte("aad"))
	ct[0] ^= 0x01
	if _, err := aead.Open(nil, nonce, ct, []byte("aad")); err == nil {
		t.Fatal("expected auth failure for AES-128 bit flip")
	}

	// Wrong AAD.
	ct2 := aead.Seal(nil, nonce, []byte("test128"), []byte("aad1"))
	if _, err := aead.Open(nil, nonce, ct2, []byte("aad2")); err == nil {
		t.Fatal("expected auth failure for AES-128 wrong AAD")
	}
}

func TestZeroClearOnAuthFailure(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, NonceSize256)
	aead, _ := NewAES256(key)

	pt := []byte("secret data that must be zeroed!")
	ct := aead.Seal(nil, nonce, pt, nil)
	ct[0] ^= 0xFF // tamper

	// Pre-allocate buffer with non-zero fill so we can detect zeroing.
	buf := make([]byte, len(pt))
	for i := range buf {
		buf[i] = 0xFF
	}
	// Pass buf[:0] as dst; sliceForAppend reuses the backing array.
	_, err := aead.Open(buf[:0], nonce, ct, nil)
	if err == nil {
		t.Fatal("expected auth failure")
	}
	// The backing array should be zeroed by Open on failure.
	for i := 0; i < len(pt); i++ {
		if buf[i] != 0 {
			t.Fatalf("output byte %d not zeroed: 0x%02x", i, buf[i])
		}
	}
}

func TestNonceSizeConsistency(t *testing.T) {
	aead256, _ := NewAES256(make([]byte, 32))
	if aead256.NonceSize() != 32 {
		t.Fatalf("AES-256 NonceSize = %d, want 32", aead256.NonceSize())
	}
	if aead256.Overhead() != 16 {
		t.Fatalf("AES-256 Overhead = %d, want 16", aead256.Overhead())
	}

	aead128, _ := NewAES128(make([]byte, 16))
	if aead128.NonceSize() != 24 {
		t.Fatalf("AES-128 NonceSize = %d, want 24", aead128.NonceSize())
	}
	if aead128.Overhead() != 16 {
		t.Fatalf("AES-128 Overhead = %d, want 16", aead128.Overhead())
	}

	// Custom tag sizes.
	for _, ts := range []int{4, 8, 12, 16} {
		a, _ := NewAES256WithTagSize(make([]byte, 32), ts)
		if a.Overhead() != ts {
			t.Fatalf("tag=%d: Overhead = %d", ts, a.Overhead())
		}
	}
}

func TestSegmentBoundaryExact(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 0xAA
	nonce := make([]byte, NonceSize256)
	nonce[0] = 0xBB

	// Test exact boundary sizes with deterministic inputs.
	for _, size := range []int{63, 64, 65, 128, 129} {
		g, _ := newGEM(key, TagSize)
		g.segSize = 64

		pt := make([]byte, size)
		for i := range pt {
			pt[i] = byte(i)
		}

		ct := g.Seal(nil, nonce, pt, nil)

		g2, _ := newGEM(key, TagSize)
		g2.segSize = 64
		got, err := g2.Open(nil, nonce, ct, nil)
		if err != nil {
			t.Fatalf("size=%d: decrypt failed: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size=%d: plaintext mismatch", size)
		}
	}

	// Verify one deterministic expected output to catch self-consistent
	// mutations in deriveSegmentKey.
	g3, _ := newGEM(key, TagSize)
	g3.segSize = 64
	pt65 := make([]byte, 65)
	for i := range pt65 {
		pt65[i] = byte(i)
	}
	ct65 := g3.Seal(nil, nonce, pt65, nil)
	split := len(ct65) - TagSize
	wantCT := "8a329b59d2728b8a5c764041dda9658a045d64375250ad1f56b63238a36507f2a9b13c747369d762f3ae0be86d07bfa8778b1f64d8e83cd632a358066bc81913d7"
	wantTag := "51f619f36fabbe31cd8872f93f66a3dd"
	if got := hex.EncodeToString(ct65[:split]); got != wantCT {
		t.Fatalf("seg-65 ct: got %s, want %s", got, wantCT)
	}
	if got := hex.EncodeToString(ct65[split:]); got != wantTag {
		t.Fatalf("seg-65 tag: got %s, want %s", got, wantTag)
	}
}

func TestAES128KeyCommitmentKnown(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, NonceSize128)

	q, err := KeyCommitment128(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	want := "ecd134d2a4a7095c1e65ae7628a182073e9273e63037f8f54d57f48f5c7d0ad4"
	if got := hex.EncodeToString(q); got != want {
		t.Fatalf("AES-128 commitment: got %s, want %s", got, want)
	}
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
