package gem

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type katFile struct {
	Algorithm  string     `json:"algorithm"`
	TestGroups []katGroup `json:"testGroups"`
}

type katGroup struct {
	GroupID int       `json:"testGroupId"`
	KeyBits int       `json:"keyBits"`
	TagBits int       `json:"tagBits"`
	Tests   []katCase `json:"tests"`
}

type katCase struct {
	ID            int    `json:"testId"`
	Description   string `json:"description"`
	Key           string `json:"key"`
	Nonce         string `json:"nonce"`
	Plaintext     string `json:"plaintext"`
	AAD           string `json:"aad"`
	Ciphertext    string `json:"ciphertext"`
	Tag           string `json:"tag"`
	KeyCommitment string `json:"keyCommitment,omitempty"`
}

func TestKATVectors(t *testing.T) {
	data, err := os.ReadFile("../../kat.json")
	if err != nil {
		t.Fatalf("read kat.json: %v", err)
	}

	var kat katFile
	if err := json.Unmarshal(data, &kat); err != nil {
		t.Fatalf("parse kat.json: %v", err)
	}

	for _, g := range kat.TestGroups {
		tagSize := g.TagBits / 8
		for _, tc := range g.Tests {
			name := tc.Description
			t.Run(name, func(t *testing.T) {
				key := mustHex(t, tc.Key)
				nonce := mustHex(t, tc.Nonce)
				pt := mustHex(t, tc.Plaintext)
				aad := mustHex(t, tc.AAD)
				wantCT := mustHex(t, tc.Ciphertext)
				wantTag := mustHex(t, tc.Tag)

				var aead interface {
					Seal(dst, nonce, pt, aad []byte) []byte
					Open(dst, nonce, ct, aad []byte) ([]byte, error)
				}
				var err error
				switch g.KeyBits {
				case 256:
					aead, err = NewAES256WithTagSize(key, tagSize)
				case 128:
					aead, err = NewAES128WithTagSize(key, tagSize)
				default:
					t.Fatalf("unsupported keyBits: %d", g.KeyBits)
				}
				if err != nil {
					t.Fatalf("new AEAD: %v", err)
				}

				// Test encryption.
				sealed := aead.Seal(nil, nonce, pt, aad)
				split := len(sealed) - tagSize
				gotCT := sealed[:split]
				gotTag := sealed[split:]

				if !bytes.Equal(gotCT, wantCT) {
					t.Errorf(
						"ciphertext mismatch\n got: %x\nwant: %x",
						gotCT, wantCT,
					)
				}
				if !bytes.Equal(gotTag, wantTag) {
					t.Errorf(
						"tag mismatch\n got: %x\nwant: %x",
						gotTag, wantTag,
					)
				}

				// Test decryption.
				got, err := aead.Open(nil, nonce, sealed, aad)
				if err != nil {
					t.Fatalf("Open failed: %v", err)
				}
				if !bytes.Equal(got, pt) {
					t.Errorf(
						"plaintext mismatch\n got: %x\nwant: %x",
						got, pt,
					)
				}

				// Test key commitment if present.
				if tc.KeyCommitment != "" {
					wantQ := mustHex(t, tc.KeyCommitment)
					var gotQ []byte
					var kcErr error
					switch g.KeyBits {
					case 256:
						gotQ, kcErr = KeyCommitment256(key, nonce)
					case 128:
						gotQ, kcErr = KeyCommitment128(key, nonce)
					}
					if kcErr != nil {
						t.Fatalf("KeyCommitment: %v", kcErr)
					}
					if !bytes.Equal(gotQ, wantQ) {
						t.Errorf(
							"commitment mismatch\n got: %x\nwant: %x",
							gotQ, wantQ,
						)
					}
				}
			})
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
