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

### DeriveSegmentKey (256-bit mode)

**Inputs**:

1. Subkey (subkey), 256 bits
2. Nonce tail (N_tail), 64 bits
3. Segment index (i), 0 to 2^29 - 1

**Algorithm**

1. Set `b0 = AES-256-ECB(subkey, N_tail || (0xFD000000_00000000 + 2 * i))`
2. Set `b1 = AES-256-ECB(subkey, N_tail || (0xFD000000_00000000 + 2 * i + 1))`
3. Return `b0 || b1`

**Output**:

A 256-bit segment encryption key.

**Comments**:

Each segment encryption key is derived from the subkey using two AES-ECB invocations on blocks in the reserved counter range (`0xFD000000_00000000` through `0xFD000000_3FFFFFFF`).

The nonce tail (N[24:32]) is included in the derivation blocks as defense in depth, providing additional nonce binding beyond the implicit binding through the subkey.

Unlike DeriveSubKey, we do not XOR the output with the subkey. The subkey is already pseudorandom (derived from AES-CBC-MAC XOR'd with K), so AES-ECB of the subkey on distinct inputs produces pseudorandom outputs without additional mixing.

### Encryption (256-bit mode)

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 256 bits
3. Plaintext (P), 0 to 2^64 - 1 bits
4. Additioal authenticated data (A), 0 to 2^64 - 1 bits
5. Authentication tag length (t), 32 to 128 bits

**Algorithm**:

1. Let `subkey = DeriveSubKey(K, N[0:24])`
2. Let `H = AES-256-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FEFFFFFF_FFFFFF{t})` where `{t}` is the tag length in bits
3. Let `j0 = N[24:32] || 0xFFFFFFFF_FFFFFFFE`
4. For `i = 0, 1, 2, ...` while P has remaining plaintext:
   1. Let `enc_key = DeriveSegmentKey(subkey, N[24:32], i)`
   2. Let `P_i` = the next `min(2^36, remaining)` bytes of P
   3. Let `C_i = AES-256-CTR32(enc_key, N[24:32] || to_be32(i) || 0x00000000, P_i)`
   4. Append `C_i` to C
5. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
6. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
7. Let `S2 = AES-256-ECB(K, S)` - GCM does not do this
8. Let `T = MSB_t(AES-256-ECB(subkey, j0) xor S2)`

**Outputs**:

1. Ciphertext, C, equal in length to the plaintext P.
2. Authentication tag, T.

**Comments**:

The internal counter is split into a 29-bit segment index and a 32-bit per-segment block counter. The 128-bit CTR input block has the structure `[N[24:32] (8 bytes)][segment_index (4 bytes)][counter32 (4 bytes)]`, where AES-CTR32 increments only the last 4 bytes.

Each segment encryption key is used for at most 2^32 AES blocks (2^36 bytes). This avoids the PRP-PRF distinguisher that weakens confidentiality when the same AES key encrypts more than 2^32 blocks. After each 2^36-byte segment, a new segment key is derived from the subkey.

The full counter value (treating the lower 8 bytes of the AES block as a 64-bit big-endian integer) can be described as `(segment_index << 32) | block_counter`. The range of counter values reachable by data encryption is [`0x00000000_00000000`, `0x1FFFFFFF_FFFFFFFF`].

We reserve internal counter values `0x20000000_00000000` through `0xFFFFFFFF_FFFFFFFF`. The allocated reserved values are:

| Counter range | Purpose |
| --- | --- |
| `0xFD000000_00000000` to `0xFD000000_3FFFFFFF` | Segment key derivation |
| `0xFEFFFFFF_FFFFFF01` to `0xFEFFFFFF_FFFFFF80` | H derivation (tag-length-specific) |
| `0xFFFFFFFF_FFFFFFFC` to `0xFFFFFFFF_FFFFFFFD` | Key commitment |
| `0xFFFFFFFF_FFFFFFFE` | j0 (tag mask) |

The encoding of lengths in the GHASH step is restricted to 2^64 bits. This limits the maximum plaintext to 2^61 bytes (2^57 AES blocks), so at most 2^25 of the 2^29 segment indices are reachable in practice.

Applications **MAY** cache the subkey for multiple encryptions if the first 192 bits of the nonce are the same, to save on subkey derivation overhead, but **MUST NOT** reuse the same 256-bit nonce twice for a given key, K.

The GHASH key, H, is derived using a block that encodes the authentication tag length. This ensures each tag length has a distinct GHASH key. Consequently, truncating a valid longer tag does not produce a valid shorter tag, because the underlying GHASH computations use different keys.

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
2. Let `H = AES-256-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FEFFFFFF_FFFFFF{t})` where `{t}` is the tag length in bits
3. Let `j0 = N[24:32] || 0xFFFFFFFF_FFFFFFFE`
4. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
5. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
6. Let `S2 = AES-256-ECB(K, S)` - GCM does not do this
7. Let `T2 = MSB_t(AES-256-ECB(subkey, j0) xor S2)`
8. Compare `T` with `T2` in constant-time. If they do not match, abort.
9. For `i = 0, 1, 2, ...` while C has remaining ciphertext:
   1. Let `enc_key = DeriveSegmentKey(subkey, N[24:32], i)`
   2. Let `C_i` = the next `min(2^36, remaining)` bytes of C
   3. Let `P_i = AES-256-CTR32(enc_key, N[24:32] || to_be32(i) || 0x00000000, C_i)`
   4. Append `P_i` to P

**Outputs**: 

1. Plaintext (P), or error.

### Key Commitment (256-bit mode)

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 256 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:24])`
2. Set `P = repeat(0, 32)`
3. Set `Q = AES-256-CTR32(subkey, N[24:32] || 0xFFFFFFFF_FFFFFFFC, P)`

**Output**:

A 256-bit value that can only be produced by a given input key.

### Verifying Key Commitment (256-bit mode)

**Inputs**:

1. Key (K), 256 bits
2. Nonce (N), 256 bits
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

1. Set `b = AES-CBC-MAC(K, N[0:24] || 0x47454D2D_313238)`
3. Return `b xor K`

**Output**:

A 128-bit subkey for use with the rest of the algorithm.

**Comments**:

The constant `0x47454D2D_313238` is the ASCII string `GEM-128`.

### DeriveSegmentKey (128-bit mode)

**Inputs**:

1. Subkey (subkey), 128 bits
2. Nonce tail (N_tail), 64 bits
3. Segment index (i), 0 to 2^29 - 1

**Algorithm**:

1. Set `b = AES-128-ECB(subkey, N_tail || (0xFD000000_00000000 + i))`
2. Return `b`

**Output**:

A 128-bit segment encryption key.

**Comments**:

The construction is similar to AES-256-GEM's DeriveSegmentKey, but requires only one AES-ECB invocation to produce a 128-bit key.

### Encryption (128-bit mode)

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 192 bits
3. Plaintext (P), 0 to 2^64 - 1 bits
4. Additional authenticated data (A), 0 to 2^64 - 1 bits
5. Authentication tag length (t), 32 to 128 bits

**Algorithm**:

1. Let `subkey = DeriveSubKey(K, N[0:16])`
2. Let `H = AES-128-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FEFFFFFF_FFFFFF{t})` where `{t}` is the tag length in bits
3. Let `j0 = N[16:24] || 0xFFFFFFFF_FFFFFFFE`
4. For `i = 0, 1, 2, ...` while P has remaining plaintext:
   1. Let `enc_key = DeriveSegmentKey(subkey, N[16:24], i)`
   2. Let `P_i` = the next `min(2^36, remaining)` bytes of P
   3. Let `C_i = AES-128-CTR32(enc_key, N[16:24] || to_be32(i) || 0x00000000, P_i)`
   4. Append `C_i` to C
5. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
6. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
7. Let `S2 = AES-128-ECB(K, S)` - GCM does not do this
8. Let `T = MSB_t(AES-128-ECB(subkey, j0) xor S2)`

**Outputs**:

1. Ciphertext, C, equal in length to the plaintext P.
2. Authentication tag, T.

**Comments**:

The construction is similar to AES-256-GEM. See the comments in the 256-bit encryption section for the rationale behind the segmented counter and tag-length-specific H derivation.

### Decryption (128-bit mode)

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 192 bits
3. Ciphertext (C), 0 to 2^64 - 1 bits
4. Authentication Tag (T), 32 to 128 bits
5. Additional authenticated data (A), 0 to 2^64 - 1 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:16])`
2. Let `H = AES-128-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FEFFFFFF_FFFFFF{t})` where `{t}` is the tag length in bits
3. Let `j0 = N[16:24] || 0xFFFFFFFF_FFFFFFFE`
4. Let `u = 128 * ceil(len(C)/128) - len(C)` and `v = 128 * ceil(len(A)/128) - len(A)`
5. Let `S = GHASH(H, A || repeat(0, v) || C || repeat(0, u) || len(A) || len(C))` where `repeat(b, x)` is a repeating sequence of length `x` bits with value `b`, as with GCM
6. Let `S2 = AES-128-ECB(K, S)` - GCM does not do this
7. Let `T2 = MSB_t(AES-128-ECB(subkey, j0) xor S2)`
8. Compare `T` with `T2` in constant-time. If they do not match, abort.
9. For `i = 0, 1, 2, ...` while C has remaining ciphertext:
   1. Let `enc_key = DeriveSegmentKey(subkey, N[16:24], i)`
   2. Let `C_i` = the next `min(2^36, remaining)` bytes of C
   3. Let `P_i = AES-128-CTR32(enc_key, N[16:24] || to_be32(i) || 0x00000000, C_i)`
   4. Append `P_i` to P

**Outputs**:

1. Plaintext (P), or error.

### Key Commitment (128-bit mode)

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 192 bits

**Algorithm**:

1. Set `subkey = DeriveSubKey(K, N[0:16])`
2. Set `P = repeat(0, 32)`
3. Set `Q = AES-128-CTR32(subkey, N[16:24] || 0xFFFFFFFF_FFFFFFFC, P)`

**Output**:

A 256-bit value that can only be produced by a given input key.

### Verifying Key Commitment (128-bit mode)

**Inputs**:

1. Key (K), 128 bits
2. Nonce (N), 192 bits
3. Commitment (Q), 256 bits

**Algorithm**:

1. Set `Q2 = KeyCommit(K, N)`
2. Compare `Q` with `Q2` in constant-time.

**Output**:

Boolean (Q == Q2)

# Implementations

* **Reference Implementation**: [Rust](ref/rust), forked from the AES-GCM crate by RustCrypto
* [Go](ref/golang)

