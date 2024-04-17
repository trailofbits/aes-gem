# Galois Extended Mode (GEM)

GEM is a block cipher mode similar to Galois/Counter Mode but with the following enhancements:

1. Nonces are now longer than 96-bit. AES-256-GEM uses 256-bit nonces, while AES-128-GEM uses 
   192-bit nonces. Consequently, you can use AES-GEM to encrypt a virtually unlimited number
   of messages under the same key.
2. The maximum length for an encrypted message is about 2 exabytes (2^61 bytes), rather than
   about 64 gigabytes (2^36 - 32 bytes).
3. The weaknesses with truncated GCM tags have been addressed at the cost of one additional 
   AES encrypt operation.

GEM achieves this with minimal overhead.

# Galois Extended Mode Algorithms

We specify AES-GEM for two key sizes (128-bit and 256-bit). The structure of the algorithm is largely the same between both modes.

We recommend AES-256-GEM rather than AES-128-GEM for most workloads.

## AES-256-GEM

AES-256-GEM uses 256-bit keys with 256-bit nonces. The first 192 bits of nonce are used to produce a 256-bit subkey. The remaining 64 bits of nonce are used for data encryption in Counter Mode.

### DeriveSubKey (256-bit mode)

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits

**Algorithm**

1. Set `b0 = AES-CBC-MAC(K, N || 0x4145532D_323536)`
2. Set `b1 = AES-CBC-MAC(K, N || 0x4145532D_47454D)`
3. Return `(b0 || b1) xor K`

**Output**:

A 256-bit subkey for use with the rest of the algorithm.

**Comments**:

The constants here, `0x4145532D_323536` and `0x4145532D_47454D` are the ASCII values for "AES-256" and "AES-GEM", respectively.

The full nonce is used for both halves, and is larger than one AES block. The constants fill
15 bytes (120 bits) of the second block, allowing exactly 1 byte of padding for AES-CBC-MAC.

AES-CBC-MAC uses an all-zero initialization vector for simplicity.

The output of the CBC-MAC calls are never revealed directly, so the additional CBC-MAC tweaks (length prefix, encrypting the last block, etc.) are not necessary for our purposes.

The output of each CBC-MAC call has about 128 bits of entropy, except that each half will never collide due to AES being a PRP rather than a PRF.

To alleviate this concern, we borrow a trick from Salsa20's design: XOR the original encryption key with the output of this function to ensure a 256-bit uniformly random distribution of bits to any attacker that doesn't already know the input key.

### Encryption (256-bit mode)

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 256 bits
3. Plaintext (P), 0 to 2^64 - 1 bits
4. Additioal authenticated data (A), 0 to 2^64 - 1 bits
5. Authentication tag length (t), 32 to 128 bits

**Algorithm**:

1. Let `subkey = DeriveSubKey(K, N[0:24])`
2. Let `H = AES-256-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)`
3. Let `j0 = N[24:32] || 0xFFFFFFFF_FFFFFFFE`
4. Let `C = AES-256-CTR(subkey, N[24:32] || 0x00000000_00000000, P)`
5. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
6. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
7. Let `S2 = AES-256-ECB(K, S)` - GCM does not do this
8. Let `T = MSB_t(AES-256-CTR(subkey, j0) xor S2)`

**Outputs**: 

1. Ciphertext, C, equal in length to the plaintext P.
2. Authentication tag, T.

**Comments**:

Where GCM uses a 32-bit internal counter, we specify 64 bits instead. The most significant 64 bits of the counter nonce are the remaining bits from the 256-bit nonce that were not used to derive a subkey.

Applications **MAY** cache the subkey for multiple encryptions if the first 192 bits of the nonce are the same, to save on subkey derivation overhead, but **MUST NOT** reuse the same 256-bit nonce twice for a given key, K.

Although a 64-bit counter would theoretically permit longer plaintexts than 2^64 bits, the encoding of lengths in the GHASH step is restricted to 2^64 bits. This is congruent to the maximum length of AAD in AES-GCM. These interal counter values are inaccessible due to GHASH length encoding.

2^64 bits is equal to 2^61 bytes (where the size of a byte is 8 bits), which is 2^57 AES blocks. The range of block counters that AES-CTR can reach can be described by the interval [`0x00000000_00000000`, `0x01ffffff_ffffffff`].

Therefore, we reserve internal counter values `0x02000000_00000000` through `0xffffffff_ffffffff`.

The counter values `0xffffffff_fffffffe` and `0xffffffff_ffffffff` are reserved for j0 (which is used to encrypt the authentication tag) and H (which is the authentication key for GHASH), respectively.

The counter values `0xffffffff_fffffffc` and `0xffffffff_fffffffd` are reserved for
calculating an optional key commitment value.

For authentication, the output of GHASH is not used directly, as with AES-GCM. Instead, the output is encrypted in ECB mode using the original key, K, rather than the subkey. This encryption of the GHASH output addresses a weakness with AES-GCM tag truncation as outlined by [Niels Ferguson in 2015](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf).

We use a keyed cipher for encrypting the GHASH output, rather than an all-zero key (which would be sufficient for non-linearity), because if an attacker does not know the AES key, they cannot decrypt this value to obtain the raw GHASH, even under a nonce reuse condition. If the universally held assumption that AES is a secure permutation holds true, this encryption of the GHASH state should also reduce the impact of a nonce reuse.

We use K here, rather than the derived subkey, for two reasons:

First, the subkey will be used for encrypting a lot of blocks. It's feasible that some (nonce || counter) block will collide with a GHASH output. Using subkey for this purpose would require extra considerations. Conversely, K is only otherwise used for key derivation in a way that is never directly revealed to attackers.

Second, this choice binds the permutation of the GHASH output to the original key. If two (key, nonce) pairs produce a subkey collision, unless K is also the same, it remains computationally infeasible to forge authentication tags for all ciphertexts.

### Decryption (256-bit mode)

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 256 bits
3. Ciphertext (C), 0 to 2^64 - 1 bits
4. Authentication Tag (T), 32 to 128 bits
5. Additioal authenticated data (A), 0 to 2^64 - 1 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:24])`
2. Let `H = AES-256-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)`
3. Let `j0 = N[24:32] || 0xFFFFFFFF_FFFFFFFE`
4. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
5. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
6. Let `S2 = AES-256-ECB(K, S)` - GCM does not do this
7. Let `T2 = MSB_t(AES-CTR(subkey, j0) xor S2)`
8. Compare `T` with `T2` in constant-time. If they do not match, abort.
9. Let `P = AES-256-CTR(subkey, N[24:32] || 0x00000000_00000000, C)`

**Outputs**: 

1. Plaintext (P), or error.

### Key Commitment

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:24])`
2. Set `P = repeat(0, 32)`
3. Set `Q = AES-256-CTR(subkey, 0xffffffff_fffffffc, P)`

**Output**:

A 256-bit value that can only be produced by a given input key.

### Verifying Key Commitment

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 192 bits
3. Commitment (Q), 256 bits

**Algorithm**:

1. Set `Q2 = KeyCommit(K, N)`
2. Compare `Q` with `Q2` in constant-time.

**Output**:

Boolean (Q == Q2)

## AES-128-GEM

AES-128-GEM uses 128-bit keys with 192-bit nonces. The first 128 bits of nonce are used to produce a 128-bit subkey. The remaining 64 bits of nonce are used with AES-128-CTR as expected.

### DeriveSubKey (128-bit mode)

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 128 bits

**Algorithm**

1. Set `b = AES-CBC-MAC(K, N[0:24] || 0x414553)`
3. Return `b xor K`

**Output**:

A 128-bit subkey for use with the rest of the algorithm.

### Encryption (128-bit mode)

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 192 bits
3. Plaintext (P), 0 to 2^64 - 1 bits
4. Additioal authenticated data (A), 0 to 2^64 - 1 bits
5. Authentication tag length (t), 32 to 128 bits

**Algorithm**:

1. Let `subkey = DeriveSubKey(K, N[0:16])`
2. Let `H = AES-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)`
3. Let `j0 = N[16:24] || 0xFFFFFFFF_FFFFFFFE`
4. Let `C = AES-128-CTR(subkey, N[16:24] || 0x00000000_00000000, P)`
5. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
6. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
7. Let `S2 = AES-128-ECB(K, S)` - GCM does not do this
8. Let `T = MSB_t(AES-128-CTR(subkey, j0) xor S2)`

**Outputs**: 

1. Ciphertext, C, equal in length to the plaintext P.
2. Authentication tag, T.

**Comments**:

The construction is similar to AES-256-GEM.

### Decryption (128-bit mode)

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 192 bits
3. Ciphertext (C), 0 to 2^64 - 1 bits
4. Authentication Tag (T), 32 to 128 bits
5. Additioal authenticated data (A), 0 to 2^64 - 1 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:16])`
2. Let `H = AES-128-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)`
3. Let `j0 = N[16:24] || 0xFFFFFFFF_FFFFFFFE`
4. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
5. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
6. Let `S2 = AES-128-ECB(K, S)` - GCM does not do this
7. Let `T2 = MSB_t(AES-128-CTR(subkey, j0) xor S2)`
8. Compare `T` with `T2` in constant-time. If they do not match, abort.
9. Let `P = AES-128-CTR(subkey, N[16:24] || 0x00000000_00000000, C)`

**Outputs**: 

1. Plaintext (P), or error.

### Key Commitment

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 128 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:16])`
2. Set `P = repeat(0, 32)`
3. Set `Q = AES-CTR(subkey, 0xffffffff_fffffffc, P)`

**Output**:

A 256-bit value that can only be produced by a given input key.

### Verifying Key Commitment

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 128 bits
3. Commitment (Q), 256 bits

**Algorithm**:

1. Set `Q2 = KeyCommit(K, N)`
2. Compare `Q` with `Q2` in constant-time.

**Output**:

Boolean (Q == Q2)

# Implementations

* **Reference Implementation**: [Rust](ref/rust), forked from the AES-GCM crate by RustCrypto
* [Go](ref/golang)

