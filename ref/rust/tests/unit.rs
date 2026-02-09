//! Unit tests to improve mutation testing coverage for AES-GEM.
//!
//! These supplement the KAT vectors in `kat.rs` with targeted tests
//! for error paths, domain separation, and deterministic intermediate
//! values that catch mutations in constants, operators, and slice indices.

use aes::Aes256;
use aes_gem::aead::{AeadInOut, KeyInit};
use aes_gem::AesGem;
use cipher::array::Array;
use cipher::consts::{U12, U13, U14, U15, U16, U32};
use hex_literal::hex;

// ---- Deterministic known-value tests ----

#[test]
fn deterministic_zero_key_empty() {
    let key = [0u8; 32];
    let nonce = Array::<u8, U32>::default();
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let mut buf = Vec::new();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
        .expect("encrypt failed");

    assert_eq!(&tag[..], &hex!("51710d926727d97eafdef7a1e8e84481"));
}

#[test]
fn deterministic_zero_key_with_aad() {
    let key = [0u8; 32];
    let nonce = Array::<u8, U32>::default();
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let mut buf = Vec::new();
    let aad = hex!("6164646974696f6e616c2064617461");
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
        .expect("encrypt failed");

    assert_eq!(&tag[..], &hex!("7b8a46e020f4da8e000d650a1a22d02e"));
}

#[test]
fn deterministic_zero_key_with_plaintext() {
    let key = [0u8; 32];
    let nonce = Array::<u8, U32>::default();
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let pt = hex!("68656c6c6f2c204145532d3235362d47454d21");
    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
        .expect("encrypt failed");

    assert_eq!(buf, hex!("f5b7a03c51ba202ab9c8dc0296dd697b025dfc"));
    assert_eq!(&tag[..], &hex!("3502a8d2342651fa1a810d9e053fede6"));
}

#[test]
fn deterministic_incrementing_key() {
    let key = hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    let nonce = Array::<u8, U32>::from(hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    ));
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let pt = hex!(
        "54686520717569636b2062726f776e20"
        "666f78206a756d7073206f7665722074"
        "6865206c617a7920646f67"
    );
    let aad = hex!("41454144206173736f6369617465642064617461");

    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
        .expect("encrypt failed");

    let want_ct = hex!(
        "737cf44ad0b728e88e4b9d81bd476d2d"
        "6496a87e9661bd0c5576a91bd0dc4d9a"
        "46f6a421942c9a4b421a53"
    );
    let want_tag = hex!("681b0552d339fd459bd94a3dc4284b79");

    assert_eq!(&buf[..], &want_ct[..]);
    assert_eq!(&tag[..], &want_tag[..]);
}

// ---- Authentication failure tests ----

#[test]
fn auth_failure_bit_flip() {
    let key = [0u8; 32];
    let nonce = Array::<u8, U32>::default();
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let mut buf = b"test data".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
        .expect("encrypt failed");

    buf[0] ^= 0x01;
    let result = cipher.decrypt_inout_detached(&nonce, b"", (&mut buf[..]).into(), &tag);
    assert!(result.is_err(), "expected auth failure on bit flip");
}

#[test]
fn auth_failure_wrong_aad() {
    let key = [0u8; 32];
    let nonce = Array::<u8, U32>::default();
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let mut buf = b"test".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"aad1", (&mut buf[..]).into())
        .expect("encrypt failed");

    let result = cipher.decrypt_inout_detached(&nonce, b"aad2", (&mut buf[..]).into(), &tag);
    assert!(result.is_err(), "expected auth failure on wrong AAD");
}

#[test]
fn auth_failure_wrong_key() {
    let key1 = [0x01u8; 32];
    let key2 = [0x02u8; 32];
    let nonce = Array::<u8, U32>::from([0xAAu8; 32]);

    let cipher1 = AesGem::<Aes256, U16>::new(&key1.into());
    let cipher2 = AesGem::<Aes256, U16>::new(&key2.into());

    let mut buf = b"secret".to_vec();
    let tag = cipher1
        .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
        .expect("encrypt failed");

    let result = cipher2.decrypt_inout_detached(&nonce, b"", (&mut buf[..]).into(), &tag);
    assert!(result.is_err(), "expected auth failure on wrong key");
}

#[test]
fn auth_failure_wrong_tag() {
    let key = [0u8; 32];
    let nonce = Array::<u8, U32>::default();
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let mut buf = b"hello".to_vec();
    let _tag = cipher
        .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
        .expect("encrypt failed");

    let bad_tag = Array::<u8, U16>::default();
    let result = cipher.decrypt_inout_detached(&nonce, b"", (&mut buf[..]).into(), &bad_tag);
    assert!(result.is_err(), "expected auth failure on wrong tag");
}

// ---- Round-trip tests ----

#[test]
fn round_trip_basic() {
    let key = [0x42u8; 32];
    let nonce = Array::<u8, U32>::from([0xABu8; 32]);
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let pt = b"hello, AES-256-GEM!";
    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"aad", (&mut buf[..]).into())
        .expect("encrypt failed");

    cipher
        .decrypt_inout_detached(&nonce, b"aad", (&mut buf[..]).into(), &tag)
        .expect("decrypt failed");
    assert_eq!(&buf[..], &pt[..]);
}

#[test]
fn round_trip_empty_plaintext() {
    let key = [0u8; 32];
    let nonce = Array::<u8, U32>::default();
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let mut buf = Vec::new();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"aad-only", (&mut buf[..]).into())
        .expect("encrypt failed");

    cipher
        .decrypt_inout_detached(&nonce, b"aad-only", (&mut buf[..]).into(), &tag)
        .expect("decrypt failed");
    assert!(buf.is_empty());
}

#[test]
fn round_trip_large_message() {
    let key = [0x99u8; 32];
    let nonce = Array::<u8, U32>::from([0x11u8; 32]);
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let pt: Vec<u8> = (0u8..=255).cycle().take(1 << 16).collect();
    let mut buf = pt.clone();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
        .expect("encrypt failed");

    cipher
        .decrypt_inout_detached(&nonce, b"", (&mut buf[..]).into(), &tag)
        .expect("decrypt failed");
    assert_eq!(buf, pt);
}

// ---- Tag domain separation ----

#[test]
fn tag_domain_separation_12_vs_16() {
    let key = [0x42u8; 32];
    let nonce = Array::<u8, U32>::from([0xABu8; 32]);
    let pt = b"domain separation test";

    let cipher12 = AesGem::<Aes256, U12>::new(&key.into());
    let cipher16 = AesGem::<Aes256, U16>::new(&key.into());

    let mut buf12 = pt.to_vec();
    let tag12 = cipher12
        .encrypt_inout_detached(&nonce, b"", (&mut buf12[..]).into())
        .expect("encrypt 12 failed");

    let mut buf16 = pt.to_vec();
    let tag16 = cipher16
        .encrypt_inout_detached(&nonce, b"", (&mut buf16[..]).into())
        .expect("encrypt 16 failed");

    // CTR doesn't depend on tag size, so ciphertext should be identical.
    assert_eq!(buf12, buf16, "ciphertext should match");
    // Tags must differ due to GHASH key domain separation.
    assert_ne!(&tag12[..], &tag16[..12], "tags should differ");
}

// ---- Tag size round-trips ----

macro_rules! tag_size_test {
    ($name:ident, $tag_ty:ty, $tag_len:expr) => {
        #[test]
        fn $name() {
            let key = [0x42u8; 32];
            let nonce = Array::<u8, U32>::from([0x01u8; 32]);
            let cipher = AesGem::<Aes256, $tag_ty>::new(&key.into());

            let pt = b"tag size test";
            let mut buf = pt.to_vec();
            let tag = cipher
                .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
                .expect("encrypt failed");
            assert_eq!(tag.len(), $tag_len);

            cipher
                .decrypt_inout_detached(&nonce, b"", (&mut buf[..]).into(), &tag)
                .expect("decrypt failed");
            assert_eq!(&buf[..], &pt[..]);
        }
    };
}

tag_size_test!(tag_size_12, U12, 12);
tag_size_test!(tag_size_13, U13, 13);
tag_size_test!(tag_size_14, U14, 14);
tag_size_test!(tag_size_15, U15, 15);
tag_size_test!(tag_size_16, U16, 16);

// ---- Deterministic tag size KAT vectors ----

#[test]
fn kat_96bit_tag() {
    let key = hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    let nonce = Array::<u8, U32>::from(hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    ));
    let cipher = AesGem::<Aes256, U12>::new(&key.into());

    let pt = hex!("68656c6c6f2c204145532d3235362d47454d21");
    let aad = hex!("6164646974696f6e616c2064617461");

    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
        .expect("encrypt failed");

    assert_eq!(&buf[..], &hex!("4f71fd06ceee61caa038d2c1e7062e4a47b4f1"));
    assert_eq!(&tag[..], &hex!("b176ea201cf7147f551532a4"));

    // Verify decryption round-trip.
    cipher
        .decrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into(), &tag)
        .expect("decrypt failed");
    assert_eq!(&buf[..], &pt[..]);
}

#[test]
fn kat_104bit_tag() {
    let key = hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    let nonce = Array::<u8, U32>::from(hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    ));
    let cipher = AesGem::<Aes256, U13>::new(&key.into());

    let pt = hex!("68656c6c6f2c204145532d3235362d47454d21");
    let aad = hex!("6164646974696f6e616c2064617461");

    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
        .expect("encrypt failed");

    assert_eq!(&tag[..], &hex!("f54baa4ea8296a5979d395b6ec"));
}

#[test]
fn kat_112bit_tag() {
    let key = hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    let nonce = Array::<u8, U32>::from(hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    ));
    let cipher = AesGem::<Aes256, U14>::new(&key.into());

    let pt = hex!("68656c6c6f2c204145532d3235362d47454d21");
    let aad = hex!("6164646974696f6e616c2064617461");

    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
        .expect("encrypt failed");

    assert_eq!(&tag[..], &hex!("2d398230b478009d35e4c40fe4f6"));
}

#[test]
fn kat_120bit_tag() {
    let key = hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    let nonce = Array::<u8, U32>::from(hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    ));
    let cipher = AesGem::<Aes256, U15>::new(&key.into());

    let pt = hex!("68656c6c6f2c204145532d3235362d47454d21");
    let aad = hex!("6164646974696f6e616c2064617461");

    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
        .expect("encrypt failed");

    assert_eq!(&tag[..], &hex!("a8889c51a771eb49552de7d885aa20"));
}

// ---- Decrypt-only deterministic vector ----

#[test]
fn decrypt_known_vector() {
    let key = hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    let nonce = Array::<u8, U32>::from(hex!(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    ));
    let cipher = AesGem::<Aes256, U16>::new(&key.into());

    let ct = hex!(
        "737cf44ad0b728e88e4b9d81bd476d2d"
        "6496a87e9661bd0c5576a91bd0dc4d9a"
        "46f6a421942c9a4b421a53"
    );
    let aad = hex!("41454144206173736f6369617465642064617461");
    let tag = Array::<u8, U16>::from(hex!("681b0552d339fd459bd94a3dc4284b79"));

    let mut buf = ct.to_vec();
    cipher
        .decrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into(), &tag)
        .expect("decrypt failed");

    let want_pt = hex!(
        "54686520717569636b2062726f776e20"
        "666f78206a756d7073206f7665722074"
        "6865206c617a7920646f67"
    );
    assert_eq!(&buf[..], &want_pt[..]);
}
