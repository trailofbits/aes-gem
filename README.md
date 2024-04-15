# Galois Extended Mode (GEM)

GEM is a block cipher mode similar to Galois/Counter Mode but with the following enhancements:

1. Nonces are now 256-bit rather than 96-bit. Consequently, you can use AES-GEM to encrypt a
   virtually unlimited number of messages under the same key, at the cost of 2 additional AES
   encrypt operations to derive a new key plus one additional AES key schedule setup.
2. The maximum length for an encrypted message is about 2 exabytes (2^61 bytes), rather than
   about 64 gigabytes (2^36 - 32 bytes).
3. The weaknesses with truncated GCM tags have been addressed at the cost of one additional 
   AES encrypt operation.

GEM achieves this with minimal overhead (3 additional AES encrypt operations) and a few XORs.

## Galois Extended Mode Algorithms

### DeriveSubKey

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits

**Algorithm**

1. Set `b0 = AES-CBC-MAC(K, N[0:12] || 0x414553)`
2. Set `b1 = AES-CBC-MAC(K, N[12:24] || 0x47454D)`
3. Return `(b0 || b1) xor K`

**Output**:

A 256-bit subkey for use with the rest of the algorithm.

**Comments**:

The constants here, `0x414553` and `0x47454D` are the ASCII values for "AES" and "GEM", respectively. Both inputs will fill up 15 bytes (120 bits), allowing exactly 1 byte of padding for AES-CBC-MAC. This minimizes the number of AES encryption calls needed for subkey derivation.

AES-CBC-MAC uses an all-zero initialization vector for simplicity.

The output of the CBC-MAC calls are never revealed directly, so the additional CBC-MAC tweaks (length prefix, encrypting the last block, etc.) are not necessary for our purposes. 

The output of each CBC-MAC call has about 128 bits of entropy, except that each half will never collide due to AES being a PRP rather than a PRF. 

To alleviate this concern, we borrow a trick from Salsa20's design: XOR the original encryption key with the output of this function to ensure a 256-bit uniformly random distribution of bits to any attacker that doesn't already know the input key.

It is also possible to implement the AES-CBC-MAC calls as direct calls to the AES block cipher, due to the message fitting in one block and the initialization vector being all zeroes.

### Encryption

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits
3. Plaintext (P), 0 to 2^64 - 1 bits
4. Additioal authenticated data (A), 0 to 2^64 - 1 bits
5. Authentication tag length (t), 32 to 128 bits

**Algorithm**:

1. Let `subkey = DeriveSubKey(K, N[0:24])`
2. Let `H = AES-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)`
3. Let `j0 = N[24:32] || 0xFFFFFFFF_FFFFFFFE`
4. Let `C = AES-CTR(subkey, N[24:32] || 0x00000000_00000000, P)`
5. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
6. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
7. Let `S2 = AES-ECB(K, S)` - GCM does not do this
8. Let `T = MSB_t(AES-CTR(subkey, j0) xor S2)`

**Outputs**: 

1. Ciphertext, C, equal in length to the plaintext P.
2. Authentication tag, T.

**Comments**:

Where GCM uses a 32-bit internal counter, we specify 64 bits instead. The most significant 64 bits of the counter nonce are the remaining bits from the 256-bit nonce that were not used to derive a subkey.

Applications **MAY** cache the subkey for multiple encryptions if the first 192 bits of the nonce are the same, to save on subkey derivation overhead, but **MUST NOT** reuse the same 256-bit nonce twice for a given key, K.

Although a 64-bit counter would theoretically permit longer plaintexts than 2^64 - 1 bits, the encoding of lengths in the GHASH step is restricted to 2^64 -1 bits. This is congruent to the maximum length of AAD in AES-GCM. These interal counter values are inaccessible due to GHASH length encoding.

Therefore, we reserve internal counter values `0x20000000_00000000` through 
`0xffffffff_ffffffff`.

The counter values `0xffffffff_fffffffe` and `0xffffffff_ffffffff` are reserved for j0 (which is used to encrypt the authentication tag) and H (which is the authentication key for GHASH).

The counter values `0xffffffff_fffffffc` and `0xffffffff_fffffffd` are reserved for
calculating an optional key commitment value.

For authentication, the output of GHASH is not used directly, as with AES-GCM. Instead, the output is encrypted in ECB mode using the original key, K, rather than the subkey. This encryption of the GHASH output addresses a weakness with AES-GCM tag truncation as outlined by [Niels Ferguson in 2015](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf).

### Decryption

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits
3. Ciphertext (C), 0 to 2^64 - 1 bits
4. Authentication Tag (T), 32 to 128 bits
5. Additioal authenticated data (A), 0 to 2^64 - 1 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:24])`
2. Let `H = AES-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)`
3. Let `j0 = N[24:32] || 0xFFFFFFFF_FFFFFFFE`
4. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
5. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
6. Let `S2 = AES-ECB(K, S)` - GCM does not do this
7. Let `T2 = MSB_t(AES-CTR(subkey, j0) xor S2)`
8. Compare `T` with `T2` in constant-time. If they do not match, abort.
9. Let `P = AES-CTR(subkey, N[24:32] || 0x00000000_00000000, C)`

**Outputs**: 

1. Plaintext (P), or error.

### Key Commitment

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:24])`
2. Set `P = repeat(0, 32)`
3. Set `Q = AES-CTR(subkey, 0xffffffff_fffffffc, P)`

**Output**:

A 256-bit value that can only be produced by a given input key.

### Verifying Key Commitment

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits
3. Commitment (Q), 256 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:24])`
2. Set `P = repeat(0, 32)`
3. Set `Q2 = AES-CTR(subkey, 0xffffffff_fffffffc, P)`
4. Compare `Q` with `Q2` in constant-time.

**Output**:

Boolean (Q == Q2)

# Implementations

* **Reference Implementation**: [Rust](ref/rust), forked from the AES-GCM crate by RustCrypto
* [Go](ref/golang)

