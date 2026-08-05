//! `ring`-backed [`ExpresslaneAead`] for ExpressLane data packets.
//!
//! Ported from the fork's `lightway-expresslane/src/cipher.rs` onto the
//! monorepo crate's `ExpresslaneAead` trait. `LessSafeKey` is the only ring
//! AEAD key type that accepts a caller-supplied nonce - `SealingKey`/
//! `OpeningKey` demand a `NonceSequence`, which cannot express "the 12-byte
//! IV arrives on the wire". The key schedule is expanded once in `new`, so
//! the per-packet path does no key setup.

use bytes::BytesMut;
use lightway_expresslane::{ExpresslaneAead, ExpresslaneError, ExpresslaneKey, ExpresslaneResult};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, Tag, UnboundKey};

/// AES-256-GCM over `ring::aead::LessSafeKey`.
pub struct RingAead(LessSafeKey);

impl ExpresslaneAead for RingAead {
    fn new(key: &ExpresslaneKey) -> ExpresslaneResult<Self> {
        // Unreachable in practice - `ExpresslaneKey.0` is `[u8; 32]` and
        // `AES_256_GCM.key_len()` is 32 - but the length check is ring's only
        // documented failure here, so map it rather than unwrap it.
        UnboundKey::new(&AES_256_GCM, &key.0)
            .map(|unbound| RingAead(LessSafeKey::new(unbound)))
            .map_err(|_| ExpresslaneError::SetKeyFailed)
    }

    fn seal(
        &self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> ExpresslaneResult<(BytesMut, [u8; 16])> {
        let mut buf = BytesMut::from(plaintext);
        let tag = self
            .0
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(iv), Aad::from(aad), &mut buf[..])
            .map_err(|_| ExpresslaneError::EncryptFailed)?;
        // AES-256-GCM's tag is 128 bits by definition, and ring caps every
        // tag it produces at the public MAX_TAG_LEN (16), so this cannot
        // fail; expressed as a fallible conversion rather than
        // `copy_from_slice` to keep a potential panic out of the packet path
        // regardless.
        let tag: [u8; 16] = tag.as_ref().try_into().map_err(|_| ExpresslaneError::EncryptFailed)?;
        Ok((buf, tag))
    }

    fn open(
        &self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<BytesMut> {
        let mut buf = BytesMut::from(ciphertext);
        self.0
            .open_in_place_separate_tag(
                Nonce::assume_unique_for_key(iv),
                Aad::from(aad),
                Tag::from(*tag),
                &mut buf[..],
                0..,
            )
            .map_err(|_| ExpresslaneError::AuthFailed)?;
        Ok(buf)
    }

    /// One memcpy (plaintext into `out`), then AES-GCM in place. `out` is
    /// exactly plaintext-sized per the trait's contract.
    fn seal_into(
        &self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<[u8; 16]> {
        out.copy_from_slice(plaintext);
        let tag = self
            .0
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(iv), Aad::from(aad), out)
            .map_err(|_| ExpresslaneError::EncryptFailed)?;
        tag.as_ref().try_into().map_err(|_| ExpresslaneError::EncryptFailed)
    }

    /// One memcpy (ciphertext into `out`), then AES-GCM in place. `out` is
    /// exactly ciphertext-sized per the trait's contract, so the plaintext
    /// length equals `out.len()`.
    ///
    /// On failure `out` holds whatever ring left there - the trait's
    /// contract says "unspecified", not "restored to ciphertext" or
    /// "zeroed". A caller that retries these bytes under a different key
    /// (the session's prev_peer fallback) always re-copies from the
    /// original, untouched `ciphertext` slice, never from `out`.
    fn open_into(
        &self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        out: &mut [u8],
    ) -> ExpresslaneResult<usize> {
        out.copy_from_slice(ciphertext);
        self.0
            .open_in_place_separate_tag(Nonce::assume_unique_for_key(iv), Aad::from(aad), Tag::from(*tag), out, 0..)
            .map_err(|_| ExpresslaneError::AuthFailed)?;
        Ok(out.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> ExpresslaneKey {
        ExpresslaneKey([b; lightway_expresslane::EXPRESSLANE_KEY_SIZE])
    }

    #[test]
    fn round_trip() {
        let aead = RingAead::new(&key(42)).unwrap();
        let (ct, tag) = aead.seal([1u8; 12], b"Hello, ExpressLane!", b"aad").unwrap();
        let pt = aead.open([1u8; 12], &ct, b"aad", &tag).unwrap();
        assert_eq!(&pt[..], b"Hello, ExpressLane!");
    }

    #[test]
    fn open_rejects_wrong_key() {
        let (ct, tag) = RingAead::new(&key(1)).unwrap().seal([7u8; 12], b"secret payload!!", b"aad").unwrap();
        let result = RingAead::new(&key(2)).unwrap().open([7u8; 12], &ct, b"aad", &tag);
        assert!(matches!(result, Err(ExpresslaneError::AuthFailed)));
    }

    #[test]
    fn open_rejects_tampered_aad() {
        let aead = RingAead::new(&key(9)).unwrap();
        let (ct, tag) = aead.seal([1u8; 12], b"payload!", b"aad-v1").unwrap();
        assert!(matches!(aead.open([1u8; 12], &ct, b"aad-v2", &tag), Err(ExpresslaneError::AuthFailed)));
    }

    /// The zero-alloc contract the shim relies on: `seal_into`/`open_into`
    /// round-trip through caller-owned buffers, no `seal`/`open` allocation
    /// involved.
    #[test]
    fn seal_into_and_open_into_round_trip() {
        let aead = RingAead::new(&key(3)).unwrap();
        let plaintext = b"zero-alloc payload";
        let mut sealed = [0u8; 18];
        let tag = aead.seal_into([4u8; 12], plaintext, b"aad", &mut sealed).unwrap();

        let mut opened = [0u8; 18];
        let n = aead.open_into([4u8; 12], &sealed, b"aad", &tag, &mut opened).unwrap();
        assert_eq!(&opened[..n], plaintext);
    }

    #[test]
    fn open_into_rejects_wrong_key() {
        let plaintext = b"zero-alloc payload";
        let mut sealed = [0u8; 18];
        let tag = RingAead::new(&key(5)).unwrap().seal_into([6u8; 12], plaintext, b"aad", &mut sealed).unwrap();

        let mut opened = [0u8; 18];
        let result = RingAead::new(&key(6)).unwrap().open_into([6u8; 12], &sealed, b"aad", &tag, &mut opened);
        assert!(matches!(result, Err(ExpresslaneError::AuthFailed)));
    }
}
