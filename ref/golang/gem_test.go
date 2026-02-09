package gem

import (
	"bytes"
	"crypto/rand"
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

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
