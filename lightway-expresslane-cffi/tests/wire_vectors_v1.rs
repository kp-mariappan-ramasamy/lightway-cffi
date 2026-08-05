//! Golden wire-format vector for protocol Version1.
//!
//! Companion to `wire_vectors.rs` (Version2), ported the same way: the
//! fork's `lightway-expresslane/tests/wire_vectors_v1.rs` pinned these bytes
//! against its own `ring`-based reimplementation; run here through the
//! `he_expresslane_*` C ABI against the monorepo crate plus this crate's
//! `RingAead` backend. The inputs are deliberately identical to
//! `GOLDEN_V2`'s, so AAD length - the `version >= Version2` boundary - is
//! the only difference between the two packets.
#![allow(clippy::undocumented_unsafe_blocks)]

use lightway_expresslane_cffi::*;

/// V1 packet, key=[0x42;32], session_id=01..08, counter=1, iv=[0x09;12],
/// plaintext="expresslane golden vector" (25 bytes), is_encoded=false.
///
/// Layout: counter(8) | iv(12) | tag(16) | data_len(2, BE) | flags(2, BE) |
/// ciphertext(25). Total 65 bytes. The flags field is present on the wire
/// for V1 as well; it is simply not bound into the AAD.
const GOLDEN_V1: &str = "0000000000000001\
090909090909090909090909\
f48a6db842e8b2f97cfbe8a39ca83464\
0019\
0000\
58b1d91834ea34259ee915adb156c9280a40229f78cd5b7e71";

/// Same inputs as `GOLDEN_V1`, at Version2 - used only by
/// `v1_and_v2_differ_only_in_the_tag` below to isolate what the version
/// boundary actually controls.
const GOLDEN_V2: &str = "0000000000000001\
090909090909090909090909\
cd57bbb8026b4faf70e457412a1f6ef6\
0019\
0000\
58b1d91834ea34259ee915adb156c9280a40229f78cd5b7e71";

const KEY: [u8; 32] = [0x42u8; 32];
const SESSION_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const IV: [u8; 12] = [0x09u8; 12];
const PLAINTEXT: &[u8] = b"expresslane golden vector";

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex vector must have an even number of digits");
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex vector is ASCII");
            u8::from_str_radix(pair, 16).expect("valid hex digit pair")
        })
        .collect()
}

#[test]
fn v1_encrypt_matches_golden_vector() {
    let session = unsafe { he_expresslane_session_create(1) };
    assert!(!session.is_null());
    assert_eq!(
        unsafe { he_expresslane_set_next_self_key(session, KEY.as_ptr()) },
        he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
    );
    unsafe { he_expresslane_promote_self_key(session) };

    let mut out = vec![0u8; he_expresslane_wire_overhead() + PLAINTEXT.len()];
    let mut out_len: usize = 0;
    let rc = unsafe {
        he_expresslane_encrypt(
            session,
            1,
            SESSION_ID.as_ptr(),
            PLAINTEXT.as_ptr(),
            PLAINTEXT.len(),
            IV.as_ptr(),
            false,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
    out.truncate(out_len);

    let expected = decode_hex(GOLDEN_V1);
    assert_eq!(
        out,
        expected,
        "V1 encrypt drifted from the pinned wire vector\n got: {}\nwant: {}",
        out.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        GOLDEN_V1,
    );

    unsafe { he_expresslane_session_destroy(session) };
}

#[test]
fn v1_golden_vector_decrypts_back_to_plaintext() {
    let receiver = unsafe { he_expresslane_session_create(1) };
    assert_eq!(
        unsafe { he_expresslane_set_peer_key(receiver, KEY.as_ptr()) },
        he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
    );

    let wire = decode_hex(GOLDEN_V1);
    let mut out = vec![0u8; PLAINTEXT.len()];
    let mut out_len: usize = 0;
    let mut is_encoded = true; // must be overwritten to false
    let rc = unsafe {
        he_expresslane_decrypt(
            receiver,
            SESSION_ID.as_ptr(),
            wire.as_ptr(),
            wire.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut is_encoded,
        )
    };
    assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
    assert_eq!(&out[..out_len], PLAINTEXT);
    assert!(!is_encoded);

    unsafe { he_expresslane_session_destroy(receiver) };
}

#[test]
fn v1_and_v2_differ_only_in_the_tag() {
    // Turns the pair of vectors into an assertion about *what* the version
    // boundary controls: AAD only. If someone makes V1 bind the flags, or
    // makes V2 stop binding them, this fails even if both files were
    // regenerated together - the ciphertexts would still match but the tags
    // would collapse to equal.
    let v1 = decode_hex(GOLDEN_V1);
    let v2 = decode_hex(GOLDEN_V2);

    assert_eq!(v1[0..20], v2[0..20], "counter and iv");
    assert_ne!(v1[20..36], v2[20..36], "tag must differ: V2 binds flags into the AAD");
    assert_eq!(v1[36..], v2[36..], "data_len, flags and ciphertext are AAD-independent");
}
