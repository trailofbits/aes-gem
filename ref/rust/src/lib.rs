#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../../../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(
    all(feature = "getrandom", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "std")),
    doc = "```ignore"
)]
//! use aes_gem::{
//!     aead::{Aead, AeadCore, KeyInit, OsRng},
//!     Aes256Gem, Nonce, Key
//! };
//!
//! # fn gen_key() -> Result<(), core::array::TryFromSliceError> {
//! // The encryption key can be generated randomly:
//! # #[cfg(all(feature = "getrandom", feature = "std"))] {
//! let key = Aes256Gem::generate_key().expect("generate key");
//! # }
//!
//! // Transformed from a byte array:
//! let key: &[u8; 32] = &[42; 32];
//! let key: &Key<Aes256Gem> = key.into();
//!
//! // Note that you can get byte array from slice using the `TryInto` trait:
//! let key: &[u8] = &[42; 32];
//! let key: [u8; 32] = key.try_into()?;
//! # Ok(()) }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Alternatively, the key can be transformed directly from a byte slice
//! // (panics on length mismatch):
//! # let key: &[u8] = &[42; 32];
//! let key = Key::<Aes256Gem>::from_slice(key);
//!
//! let cipher = Aes256Gem::new(&key);
//! let nonce = Aes256Gem::generate_nonce()?; // 96-bits; unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInPlace::encrypt_in_place`] and [`AeadInPlace::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the [`aead`] crate as [`aead::heapless::Vec`]),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```ignore
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use aes_gem::{
//!     aead::{AeadCore, AeadInPlace, KeyInit, OsRng, heapless::Vec},
//!     Aes256Gem, Nonce
//! };
//!
//! let key = Aes256Gem::generate_key()?;
//! let cipher = Aes256Gem::new(&key);
//! let nonce = Aes256Gem::generate_nonce()?; // 256-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(&buffer, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! Similarly, enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]).

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser};

#[cfg(feature = "aes")]
pub use aes;

use cipher::{
    array::Array,
    consts::{U16, U32},
    BlockCipherEncrypt, BlockSizeUser, InnerIvInit,
    StreamCipherCore,
};
use core::marker::PhantomData;
use ghash::{universal_hash::UniversalHash, GHash};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "aes")]
use aes::Aes256;

/// Maximum length of associated data (2^61 bytes).
pub const A_MAX: u64 = 1 << 61;

/// Maximum length of plaintext (2^61 bytes).
pub const P_MAX: u64 = 1 << 61;

/// Maximum length of ciphertext including authentication tag.
pub const C_MAX: u64 = (1 << 61) + 16;

/// Maximum bytes per CTR segment before re-keying (2^36).
const BYTES_PER_SEGMENT: u64 = 1u64 << 36;

/// Base counter value for segment key derivation (reserved range).
const SEG_KEY_BASE: u64 = 0xFD00000000000000;

/// AES-GEM nonces.
pub type Nonce<NonceSize> = Array<u8, NonceSize>;

/// AES-GEM tags.
pub type Tag<TagSize = U16> = Array<u8, TagSize>;

/// Trait implemented for valid tag sizes, i.e.
/// [`U12`][consts::U12], [`U13`][consts::U13], [`U14`][consts::U14],
/// [`U15`][consts::U15] and [`U16`][consts::U16].
pub trait TagSize: private::SealedTagSize {}

impl<T: private::SealedTagSize> TagSize for T {}

mod private {
    use cipher::array::{ArraySize, typenum::Unsigned};
    use cipher::consts;

    pub trait SealedTagSize: ArraySize + Unsigned {}

    impl SealedTagSize for consts::U12 {}
    impl SealedTagSize for consts::U13 {}
    impl SealedTagSize for consts::U14 {}
    impl SealedTagSize for consts::U15 {}
    impl SealedTagSize for consts::U16 {}
}

/// AES-256-GEM with 128-bit authentication tag.
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes256Gem = AesGem<Aes256, U16>;

/// AES block (128 bits).
type Block = Array<u8, U16>;

/// Counter mode with a 32-bit big-endian counter.
type Ctr32BE<Aes> = ctr::CtrCore<Aes, ctr::flavors::Ctr32BE>;

/// AES-GEM: Galois Extended Mode.
///
/// Generic over an underlying AES implementation. Currently only
/// AES-256 is fully implemented (via the [`Aes256Gem`] type alias).
///
/// The `TagSize` generic parameter controls authentication tag length.
/// Each tag size produces a distinct GHASH key via domain separation.
#[derive(Clone)]
pub struct AesGem<Aes, TagSize = U16>
where
    Aes: KeySizeUser,
    TagSize: self::TagSize,
{
    /// AES cipher initialized with the original key K.
    cipher: Aes,

    /// Raw key bytes for the XOR step in DeriveSubKey.
    key_bytes: Key<Aes>,

    /// Tag size marker.
    tag_size: PhantomData<TagSize>,
}

impl<Aes, TagSize> KeySizeUser for AesGem<Aes, TagSize>
where
    Aes: KeySizeUser,
    TagSize: self::TagSize,
{
    type KeySize = Aes::KeySize;
}

impl<Aes, TagSize> KeyInit for AesGem<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16>
        + BlockCipherEncrypt
        + KeyInit,
    TagSize: self::TagSize,
{
    fn new(key: &Key<Self>) -> Self {
        Self {
            cipher: Aes::new(key),
            key_bytes: key.clone(),
            tag_size: PhantomData,
        }
    }
}

impl<Aes, TagSize> AeadCore for AesGem<Aes, TagSize>
where
    Aes: KeySizeUser,
    TagSize: self::TagSize,
{
    type NonceSize = U32;
    type TagSize = TagSize;
    const TAG_POSITION: aead::TagPosition =
        aead::TagPosition::Postfix;
}

impl<Aes, TagSize> AeadInOut for AesGem<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16>
        + BlockCipherEncrypt
        + KeyInit,
    TagSize: self::TagSize,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: inout::InOutBuf<'_, '_, u8>,
    ) -> aead::Result<aead::Tag<Self>> {
        if buffer.len() as u64 > P_MAX
            || associated_data.len() as u64 > A_MAX
        {
            return Err(Error);
        }

        // Copy plaintext to output, then encrypt in-place.
        let out = buffer.into_out_with_copied_in();

        let nonce_tail = &nonce[24..32];
        let subkey = self.derive_subkey(&nonce[..24]);
        let ghash = Self::derive_ghash(&subkey);
        let tag_mask =
            Self::compute_j0_mask(&subkey, nonce_tail);

        Self::apply_segmented_ctr(&subkey, nonce_tail, out);

        let full_tag = self.compute_tag(
            ghash, tag_mask, associated_data, out,
        );
        let mut tag = aead::Tag::<Self>::default();
        tag.copy_from_slice(
            &full_tag[..TagSize::to_usize()],
        );
        Ok(tag)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: inout::InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        if buffer.len() as u64 > C_MAX
            || associated_data.len() as u64 > A_MAX
        {
            return Err(Error);
        }

        let nonce_tail = &nonce[24..32];
        let subkey = self.derive_subkey(&nonce[..24]);
        let ghash = Self::derive_ghash(&subkey);
        let tag_mask =
            Self::compute_j0_mask(&subkey, nonce_tail);

        // Verify tag over ciphertext (input side).
        let expected = self.compute_tag(
            ghash, tag_mask, associated_data,
            buffer.get_in(),
        );

        use subtle::ConstantTimeEq;
        if !bool::from(
            expected[..TagSize::to_usize()]
                .ct_eq(&tag[..]),
        ) {
            return Err(Error);
        }

        // Copy ciphertext to output, then decrypt in-place.
        let out = buffer.into_out_with_copied_in();
        Self::apply_segmented_ctr(
            &subkey, nonce_tail, out,
        );
        Ok(())
    }
}

impl<Aes, TagSize> AesGem<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16>
        + BlockCipherEncrypt
        + KeyInit,
    TagSize: self::TagSize,
{
    /// DeriveSubKey (256-bit mode):
    ///
    ///   b0 = AES-CBC-MAC(K, N[0:24] || "AES-256" || 0x80)
    ///   b1 = AES-CBC-MAC(K, N[0:24] || "AES-GEM" || 0x80)
    ///   subkey = (b0 || b1) XOR K
    fn derive_subkey(&self, nonce_head: &[u8]) -> Aes {
        // CBC-MAC block 1: E(K, N[0:16])
        let mut state = Block::default();
        state.copy_from_slice(&nonce_head[..16]);
        self.cipher.encrypt_block(&mut state);

        // b0 = E(K, state XOR (N[16:24] || "AES-256" || 0x80))
        let mut b0 = Block::default();
        b0[..8].copy_from_slice(&nonce_head[16..24]);
        b0[8..15].copy_from_slice(b"AES-256");
        b0[15] = 0x80;
        for (a, s) in b0.iter_mut().zip(state.iter()) {
            *a ^= *s;
        }
        self.cipher.encrypt_block(&mut b0);

        // b1 = E(K, state XOR (N[16:24] || "AES-GEM" || 0x80))
        let mut b1 = Block::default();
        b1[..8].copy_from_slice(&nonce_head[16..24]);
        b1[8..15].copy_from_slice(b"AES-GEM");
        b1[15] = 0x80;
        for (a, s) in b1.iter_mut().zip(state.iter()) {
            *a ^= *s;
        }
        self.cipher.encrypt_block(&mut b1);

        // subkey = (b0 || b1) XOR K
        let mut sk = Key::<Aes>::default();
        sk[..16].copy_from_slice(&b0);
        sk[16..].copy_from_slice(&b1);
        for (a, k) in sk.iter_mut().zip(self.key_bytes.iter()) {
            *a ^= *k;
        }

        #[cfg(feature = "zeroize")]
        {
            b0.zeroize();
            b1.zeroize();
            state.zeroize();
        }

        Aes::new(&sk)
    }

    /// DeriveSegmentKey (256-bit mode):
    ///
    ///   b0 = AES-ECB(subkey, N_tail || (0xFD000000_00000000 + 2*i))
    ///   b1 = AES-ECB(subkey, N_tail || (0xFD000000_00000000 + 2*i+1))
    ///   return b0 || b1
    fn derive_segment_key(
        subkey: &Aes,
        nonce_tail: &[u8],
        seg_idx: u32,
    ) -> Aes {
        let i = seg_idx as u64;

        let mut b0 = Block::default();
        b0[..8].copy_from_slice(nonce_tail);
        b0[8..16].copy_from_slice(
            &(SEG_KEY_BASE + 2 * i).to_be_bytes(),
        );
        subkey.encrypt_block(&mut b0);

        let mut b1 = Block::default();
        b1[..8].copy_from_slice(nonce_tail);
        b1[8..16].copy_from_slice(
            &(SEG_KEY_BASE + 2 * i + 1).to_be_bytes(),
        );
        subkey.encrypt_block(&mut b1);

        let mut sk = Key::<Aes>::default();
        sk[..16].copy_from_slice(&b0);
        sk[16..].copy_from_slice(&b1);

        #[cfg(feature = "zeroize")]
        {
            b0.zeroize();
            b1.zeroize();
        }

        Aes::new(&sk)
    }

    /// Derive GHASH key H with tag-length domain separation.
    ///
    /// H = AES-ECB(subkey, 0xFFFFFFFF_FFFFFFFF_FEFFFFFF_FFFFFF{t})
    /// where t = tag length in bits.
    fn derive_ghash(subkey: &Aes) -> GHash {
        let tag_bits = (TagSize::to_usize() * 8) as u8;
        let mut h_block = Block::default();
        for byte in h_block.iter_mut() {
            *byte = 0xFF;
        }
        h_block[8] = 0xFE;
        h_block[15] = tag_bits;
        subkey.encrypt_block(&mut h_block);

        let ghash = GHash::new(&h_block);

        #[cfg(feature = "zeroize")]
        h_block.zeroize();

        ghash
    }

    /// Compute j0 tag mask: AES-ECB(subkey, j0).
    ///
    /// j0 = N[24:32] || 0xFFFFFFFF_FFFFFFFE
    fn compute_j0_mask(subkey: &Aes, nonce_tail: &[u8]) -> Block {
        let mut j0 = Block::default();
        j0[..8].copy_from_slice(nonce_tail);
        for i in 8..15 {
            j0[i] = 0xFF;
        }
        j0[15] = 0xFE;
        subkey.encrypt_block(&mut j0);
        j0
    }

    /// Encrypt or decrypt using segmented AES-CTR32.
    ///
    /// Each segment derives a fresh key for at most 2^32 blocks.
    fn apply_segmented_ctr(
        subkey: &Aes,
        nonce_tail: &[u8],
        buffer: &mut [u8],
    ) {
        let mut offset = 0usize;
        let mut seg_idx = 0u32;

        while offset < buffer.len() {
            let seg_key = Self::derive_segment_key(
                subkey, nonce_tail, seg_idx,
            );

            // IV: N[24:32] || to_be32(seg_idx) || 0x00000000
            let mut iv = Block::default();
            iv[..8].copy_from_slice(nonce_tail);
            iv[8..12].copy_from_slice(&seg_idx.to_be_bytes());

            let remaining = buffer.len() - offset;
            let seg_len = core::cmp::min(
                BYTES_PER_SEGMENT,
                remaining as u64,
            ) as usize;

            let ctr = Ctr32BE::inner_iv_init(
                seg_key, &iv,
            );
            let seg = &mut buffer[offset..offset + seg_len];
            ctr.apply_keystream_partial(seg.into());

            offset += seg_len;
            seg_idx += 1;
        }
    }

    /// Compute authentication tag.
    ///
    /// S = GHASH(H, AAD || pad || C || pad || len(A) || len(C))
    /// S2 = AES-ECB(K, S)   (uses original key, not subkey)
    /// T = tag_mask XOR S2
    fn compute_tag(
        &self,
        mut ghash: GHash,
        tag_mask: Block,
        associated_data: &[u8],
        buffer: &[u8],
    ) -> Block {
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let ad_bits = (associated_data.len() as u64) * 8;
        let buf_bits = (buffer.len() as u64) * 8;

        let mut len_block = Block::default();
        len_block[..8].copy_from_slice(&ad_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&buf_bits.to_be_bytes());
        ghash.update(&[len_block]);

        let mut tag = ghash.finalize();

        // S2 = AES-ECB(K, S): encrypt with original key, not subkey.
        // This makes the tag non-linear with respect to H, addressing
        // the Ferguson truncation weakness.
        self.cipher.encrypt_block(&mut tag);

        // T = tag_mask XOR S2
        for (a, b) in tag.iter_mut().zip(tag_mask.iter()) {
            *a ^= *b;
        }

        tag
    }
}
