#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
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
    all(feature = "getrandom", feature = "heapless", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "heapless", feature = "std")),
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
#![cfg_attr(
    all(feature = "getrandom", feature = "heapless", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "heapless", feature = "std")),
    doc = "```ignore"
)]
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

pub use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};

#[cfg(feature = "aes")]
pub use aes;

use cipher::{
    array::{Array, ArraySize},
    consts::{U0, U16, U32},
    BlockCipher, BlockCipherEncrypt, BlockSizeUser, InnerIvInit, StreamCipherCore,
};
use core::marker::PhantomData;
use ghash::{universal_hash::UniversalHash, GHash};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "aes")]
use aes::{cipher::consts::U32, Aes256};

/// Maximum length of associated data.
pub const A_MAX: u64 = 1 << 61;

/// Maximum length of plaintext.
pub const P_MAX: u64 = 1 << 61;

/// Maximum length of ciphertext. Includes authentication tag.
pub const C_MAX: u64 = (1 << 61) + 16;

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
    use cipher::{array::ArraySize, consts, Unsigned};

    // Sealed traits stop other crates from implementing any traits that use it.
    pub trait SealedTagSize: ArraySize + Unsigned {}

    impl SealedTagSize for consts::U12 {}
    impl SealedTagSize for consts::U13 {}
    impl SealedTagSize for consts::U14 {}
    impl SealedTagSize for consts::U15 {}
    impl SealedTagSize for consts::U16 {}
}

/// AES-GEM with a 256-bit key and 256-bit nonce.
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes256Gem = AesGem<Aes256, U32>;

/// AES block.
type Block = Array<u8, U16>;

/// Counter mode with a 32-bit big endian counter.
type Ctr64BE<Aes> = ctr::CtrCore<Aes, ctr::flavors::Ctr64BE>;

/// AES-GEM: generic over an underlying AES implementation and nonce size.
///
/// This type is generic to support substituting alternative AES implementations
/// (e.g. embedded hardware implementations)
///
/// It is NOT intended to be instantiated with any block cipher besides AES!
/// Doing so runs the risk of unintended cryptographic properties!
///
/// The `TagSize` generic parameter can be used to instantiate AES-GEM with other
/// authorization tag sizes, however it's recommended to use it with `typenum::U16`,
/// the default of 128-bits.
///
/// If in doubt, use the built-in [`Aes256Gem`] type alias.
#[derive(Clone)]
pub struct AesGem<Aes, TagSize = U16>
where
    TagSize: self::TagSize,
{
    /// Encryption cipher.
    cipher: Aes,

    /// We need to persist a copy of the key in order to derive subkeys
    key: Key,

    /// GHASH authenticator.
    ghash: GHash,

    /// Length of the tag.
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
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
    TagSize: self::TagSize,
{
    fn new(key: &Key<Self>) -> Self {
        Aes::new(key).into()
    }
}

impl<Aes, TagSize> From<Aes> for AesGem<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: self::TagSize,
{
    fn from(cipher: Aes, key: Key) -> Self {
        let mut ghash_key = ghash::Key::default();
        /// This is a slight departure from GCM, which used an all-zero block:
        /// AES-GEM uses a GHASH key where every bit is set.
        for i in 0..16 {
            ghash_key[i] = 0xff;
        }
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);

        #[cfg(feature = "zeroize")]
        ghash_key.zeroize();

        /// We need the key for subkey derivation
        Self {
            cipher,
            key,
            ghash,
            tag_size: PhantomData,
        }
    }
}

impl<Aes, TagSize> AeadCore for AesGem<Aes, TagSize>
where
    TagSize: self::TagSize,
{
    type TagSize = TagSize;
    type CiphertextOverhead = U0;
}

impl<Aes, TagSize> AeadInPlace for AesGem<Aes, TagSize>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: self::TagSize,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<U32>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<TagSize>, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }
        let inner_cipher = self.derive_subkey(nonce);
        let (ctr, mask) = self.init_ctr(inner_cipher, nonce;

        ctr.apply_keystream_partial(buffer.into());

        let full_tag = self.compute_tag(inner_cipher, mask, associated_data, buffer);
        Ok(Tag::clone_from_slice(&full_tag[..TagSize::to_usize()]))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<TagSize>,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let inner_cipher = self.derive_key(nonce);
        let (ctr, mask) = self.init_ctr(inner_cipher, nonce);

        let expected_tag = self.compute_tag(inner_cipher, mask, associated_data, buffer);

        use subtle::ConstantTimeEq;
        if expected_tag[..TagSize::to_usize()].ct_eq(tag).into() {
            ctr.apply_keystream_partial(buffer.into());
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<Aes, TagSize> AesGem<Aes, TagSize>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: self::TagSize,
{
    fn derive_subkey(&self, nonce: &Nonce<NonceSize>) -> Result<Cipher, Error> {
        let mut b0 = ghash::Block::default();
        let mut b1 = ghash::Block::default();
        /// b0 = E(k,  n[0:12] || "AES" || 0x80)
        /// b1 = E(k, n[12:24] || "GEM" || 0x80)
        b0[..12].copy_from_slice(nonce[0:12]);
        b0[12] = 0x41;
        b0[13] = 0x45;
        b0[14] = 0x53;
        b0[15] = 0x80; // Padding used by CBC-MAC
        b1[..12].copy_from_slice(nonce[12:24]);
        b1[12] = 0x47;
        b1[13] = 0x45;
        b1[14] = 0x4D;
        b0[16] = 0x80; // Padding used by CBC-MAC
        self.cipher.encrypt_block(b0);
        self.cipher.encrypt_block(b1);
        let mut subkey = [&b0, &b1].concat();
        for (a, b) in subkey.as_mut_slice().iter_mut().zip(self.key.as_slice()) {
            *a ^= *b;
        }
        /// Final subkey for this nonce: (b0 || b1) xor (key)
        Ok(Aes256::new(Key::from(subkey.into())));
    }

    /// Initialize counter mode.
    /// 
    /// 
    fn init_ctr(&self, cipher: BlockCipher, nonce: &Nonce<NonceSize>) -> (Ctr64BE<&Aes>, Block) {
        let mut j0 = ghash::Block::default();
        /// AES-GEM: j0 is defined as the block when the internal counter = 0xffffffff_fffffffe
        j0[..8].copy_from_slice(nonce);
        for i in 8..16 {
            j0[i] = 0xff;
        }
        j0[15] = 0xfe;
        let mut ctr = Ctr64BE::inner_iv_init(cipher, &j0);
        let mut tag_mask = Block::default();
        ctr.write_keystream_block(&mut tag_mask);

        /// AES-GEM begins with the counter block = 0 rather than 2
        /// This is because the 64-bit counter space gives us room for H and j0
        /// derivation that the counter can never reach.
        ///
        /// (It is limited to 2^61 bytes, which means any counter above 2^57 is
        /// unreachable by AES-CTR. We use the highest values for internal purposes.)
        for i in 8..16 {
            j0[i] = 0;
        }
        let mut ctr = Ctr64BE::inner_iv_init(cipher, &j0);
        (ctr, tag_mask)
    }

    /// Authenticate the given plaintext and associated data using GHASH.
    fn compute_tag(&self, cipher: BlockCipher, mask: Block, associated_data: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&[block]);
        let mut tag = ghash.finalize();
        /// AES-GEM encrypts the GHASH state before the final XOR with the keystream block.
        /// This encryption uses the outer cipher with the original key.
        /// It does not use the inner cipher with the derived subkey.
        ///
        /// This tweak makes the authentication tag's relationship with the ciphertext and
        /// AAD non-linear with respect to H.
        ///
        /// The GHASH key, H, was calculaed from the subkey. If the GHASH output
        /// could be crafted to produce an all-set block, then the auth tag would be
        /// equal to j0 ^ H.
        ///
        /// By not using the subkey here, even a maliciously crafted GHASH output would not 
        /// learn anything about H or subkey, even if they somehow know j0.
        ///
        /// If this is ever discovered to not be sufficient key independence, we could 
        /// derive a separate subkey for this GHASH nonlinear permutation; i.e.
        ///
        /// E(k, 0xffffffff_ffffffff_ffffffff_fffffffa) = sk2
        /// S = E(sk2, GHASH(...))
        /// tag = S ^ j0
        ///
        /// For now though, this is faster and the security should be >= AES-GCM.
        self.cipher.encrypt_block(tag);
        for (a, b) in tag.as_mut_slice().iter_mut().zip(mask.as_slice()) {
            *a ^= *b;
        }

        tag
    }
}
