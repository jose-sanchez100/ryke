//! IKEv1 key schedule and encryption (RFC 2409 §5 + Appendix B).
//!
//! IKEv1 keying is structurally different from IKEv2: a raw-keyed PRF used with
//! explicit `| 0 | 1 | 2` counters (no `prf+`), a `SKEYID → SKEYID_d/a/e` chain,
//! the Phase-1 authentication `HASH_I`/`HASH_R`, a `KEYMAT` for the Quick-Mode
//! ESP SA, and AES-CBC with an IV that is *chained* across messages and reseeded
//! per Message-ID.
//!
//! The PRF is `HMAC-<hash>` for the negotiated Phase-1 hash. We support the two
//! algorithms that matter for the Android interop target (SHA-256 preferred,
//! SHA-1 as a fallback); MD5 / SHA-384 / SHA-512 can slot in behind [`Prf`].

use crate::error::IkeError;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Des3CbcEnc = cbc::Encryptor<des::TdesEde3>;
type Des3CbcDec = cbc::Decryptor<des::TdesEde3>;

/// AES block size — the CBC IV and padding granularity.
pub const AES_BLOCK: usize = 16;

/// TripleDES-CBC block size (RFC 2451's 64-bit DES block, unlike AES's
/// 128-bit one) -- RFC 4109 §3's historical mandatory-to-implement IKEv1
/// Phase-1 cipher. This crate's own initiator never offers it (see
/// `phase1::initiator_sa`'s doc); it's only ever negotiated when acting as a
/// responder against a peer whose offer carries no acceptable AES-CBC
/// transform at all (see `phase1::select_transform`).
pub const DES3_BLOCK: usize = 8;

/// The negotiated Phase-1 PRF / hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    Sha1,
    Sha256,
}

impl Prf {
    /// Output length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Prf::Sha1 => 20,
            Prf::Sha256 => 32,
        }
    }

    /// `HMAC-<hash>(key, data)` — the IKEv1 PRF.
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Prf::Sha1 => {
                let mut m = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Prf::Sha256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }

    /// The bare hash (used for the CBC IV derivation, RFC 2409 App. B).
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Prf::Sha1 => Sha1::digest(data).to_vec(),
            Prf::Sha256 => Sha256::digest(data).to_vec(),
        }
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// `SKEYID = prf(pre-shared-key, Ni_b | Nr_b)` for PSK authentication.
pub fn skeyid_psk(prf: Prf, psk: &[u8], ni: &[u8], nr: &[u8]) -> Vec<u8> {
    prf.mac(psk, &cat(&[ni, nr]))
}

/// `SKEYID = prf(Ni_b | Nr_b, g^xy)` for RSA-signature authentication (RFC
/// 2409 §5.1). Mirrors `skeyid_psk` with the key/data roles swapped: the
/// nonces become the PRF key, and the DH shared secret is the data (there is
/// no pre-shared key in this mode). Confirmed against isakmpd's
/// `sig_gen_skeyid` (`ike_auth.c`), which both DSS and RSA signature
/// authentication share.
pub fn skeyid_sig(prf: Prf, ni: &[u8], nr: &[u8], gxy: &[u8]) -> Vec<u8> {
    prf.mac(&cat(&[ni, nr]), gxy)
}

/// `SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)`.
pub fn skeyid_d(prf: Prf, skeyid: &[u8], gxy: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[gxy, cky_i, cky_r, &[0]]))
}

/// `SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)`.
pub fn skeyid_a(prf: Prf, skeyid: &[u8], skeyid_d: &[u8], gxy: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[skeyid_d, gxy, cky_i, cky_r, &[1]]))
}

/// `SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)`.
pub fn skeyid_e(prf: Prf, skeyid: &[u8], skeyid_a: &[u8], gxy: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[skeyid_a, gxy, cky_i, cky_r, &[2]]))
}

/// `HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)`.
#[allow(clippy::too_many_arguments)]
pub fn hash_i(prf: Prf, skeyid: &[u8], gx_i: &[u8], gx_r: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8], sa_b: &[u8], id_b: &[u8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[gx_i, gx_r, cky_i, cky_r, sa_b, id_b]))
}

/// `HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)`.
#[allow(clippy::too_many_arguments)]
pub fn hash_r(prf: Prf, skeyid: &[u8], gx_r: &[u8], gx_i: &[u8], cky_r: &[u8; 8], cky_i: &[u8; 8], sa_b: &[u8], id_b: &[u8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[gx_r, gx_i, cky_r, cky_i, sa_b, id_b]))
}

/// Expand `SKEYID_e` into a cipher key of `key_len` bytes (RFC 2409 App. B): the
/// first `key_len` bytes of `SKEYID_e` if long enough, else
/// `K1 = prf(SKEYID_e, 0) ; Kn = prf(SKEYID_e, K(n-1))`, concatenated.
pub fn derive_cipher_key(prf: Prf, skeyid_e: &[u8], key_len: usize) -> Vec<u8> {
    if skeyid_e.len() >= key_len {
        return skeyid_e[..key_len].to_vec();
    }
    let mut ka = Vec::new();
    let mut prev = prf.mac(skeyid_e, &[0u8]);
    ka.extend_from_slice(&prev);
    while ka.len() < key_len {
        prev = prf.mac(skeyid_e, &prev);
        ka.extend_from_slice(&prev);
    }
    ka.truncate(key_len);
    ka
}

fn keymat_inner(prf: Prf, skeyid_d: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = prf.mac(skeyid_d, seed);
    out.extend_from_slice(&prev);
    while out.len() < out_len {
        // K(n) = prf(SKEYID_d, K(n-1) | <seed>)
        let mut input = prev.clone();
        input.extend_from_slice(seed);
        prev = prf.mac(skeyid_d, &input);
        out.extend_from_slice(&prev);
    }
    out.truncate(out_len);
    out
}

/// Quick-Mode ESP keying material (RFC 2409 §5.5, no PFS):
/// `KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b)`, expanded by feedback
/// to `out_len` bytes.
pub fn keymat(prf: Prf, skeyid_d: &[u8], protocol: u8, spi: &[u8], ni: &[u8], nr: &[u8], out_len: usize) -> Vec<u8> {
    keymat_inner(prf, skeyid_d, &cat(&[&[protocol], spi, ni, nr]), out_len)
}

/// Like [`keymat`], but for the **PFS** variant of Quick Mode (RFC 2409
/// §5.5): `KEYMAT = prf(SKEYID_d, g(qm)^xy | protocol | SPI | Ni_b | Nr_b)`,
/// with the fresh Quick-Mode Diffie-Hellman `shared_secret` folded into every
/// feedback block's seed alongside the fixed protocol/SPI/nonce inputs.
#[allow(clippy::too_many_arguments)]
pub fn keymat_pfs(
    prf: Prf,
    skeyid_d: &[u8],
    shared_secret: &[u8],
    protocol: u8,
    spi: &[u8],
    ni: &[u8],
    nr: &[u8],
    out_len: usize,
) -> Vec<u8> {
    keymat_inner(prf, skeyid_d, &cat(&[shared_secret, &[protocol], spi, ni, nr]), out_len)
}

/// The Phase-1 CBC IV seed: `HASH(g^xi | g^xr)`, truncated to the block size.
pub fn phase1_iv(prf: Prf, gx_i: &[u8], gx_r: &[u8], block: usize) -> Vec<u8> {
    let mut h = prf.hash(&cat(&[gx_i, gx_r]));
    h.truncate(block);
    h
}

/// The initial IV for a post-Phase-1 exchange with `message_id`:
/// `HASH(last_phase1_iv | message_id)`, truncated to the block size.
pub fn phase2_iv(prf: Prf, phase1_iv: &[u8], message_id: u32, block: usize) -> Vec<u8> {
    let mut h = prf.hash(&cat(&[phase1_iv, &message_id.to_be_bytes()]));
    h.truncate(block);
    h
}

/// Zero-pad `data` up to a multiple of `block` (IKEv1 pads to the cipher block;
/// the real length is delimited by the ISAKMP length fields).
pub fn pad_to_block(data: &[u8], block: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    let rem = out.len() % block;
    if rem != 0 {
        out.resize(out.len() + (block - rem), 0);
    }
    out
}

/// AES-CBC encrypt (raw, no padding). `plaintext` must be block-aligned.
/// `key` selects the variant: 16 bytes = AES-128, 24 = AES-192, 32 = AES-256
/// (RFC 2409 negotiates the width via the SA's `KEY_LENGTH` attribute — see
/// [`super::phase1::InitiatorConfig::key_len`]).
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    if plaintext.len() % AES_BLOCK != 0 {
        return Err(IkeError::Crypto("CBC plaintext not block-aligned"));
    }
    let bad_key = || IkeError::Crypto("bad AES-CBC key/iv");
    Ok(match key.len() {
        16 => Aes128CbcEnc::new_from_slices(key, iv).map_err(|_| bad_key())?.encrypt_padded_vec_mut::<NoPadding>(plaintext),
        24 => Aes192CbcEnc::new_from_slices(key, iv).map_err(|_| bad_key())?.encrypt_padded_vec_mut::<NoPadding>(plaintext),
        32 => Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| bad_key())?.encrypt_padded_vec_mut::<NoPadding>(plaintext),
        _ => return Err(IkeError::Crypto("unsupported AES-CBC key length (need 16/24/32 bytes)")),
    })
}

/// AES-CBC decrypt (raw, no padding). Returns the full padded plaintext; the
/// caller uses ISAKMP length fields to find the real end. See
/// [`aes_cbc_encrypt`] for the key-length-selects-variant convention.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, IkeError> {
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK != 0 {
        return Err(IkeError::Crypto("CBC ciphertext not block-aligned"));
    }
    let bad_key = || IkeError::Crypto("bad AES-CBC key/iv");
    let bad_ct = || IkeError::Crypto("AES-CBC decrypt failed");
    match key.len() {
        16 => Aes128CbcDec::new_from_slices(key, iv).map_err(|_| bad_key())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| bad_ct()),
        24 => Aes192CbcDec::new_from_slices(key, iv).map_err(|_| bad_key())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| bad_ct()),
        32 => Aes256CbcDec::new_from_slices(key, iv).map_err(|_| bad_key())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| bad_ct()),
        _ => Err(IkeError::Crypto("unsupported AES-CBC key length (need 16/24/32 bytes)")),
    }
}

/// The last ciphertext block — becomes the IV for the next message with the same
/// Message-ID (RFC 2409 App. B CBC chaining).
pub fn next_iv(ciphertext: &[u8], block: usize) -> Vec<u8> {
    ciphertext[ciphertext.len().saturating_sub(block)..].to_vec()
}

/// TripleDES-CBC encrypt (raw, no padding). `plaintext` must be block-aligned.
/// `key` must be exactly 24 bytes (EDE3 / "keying option 1", RFC 2451 §3,
/// three independent DES keys) -- unlike AES-CBC, IKEv1 doesn't negotiate a
/// variable width for this transform (no `KEY_LENGTH` attribute is sent).
pub fn des3_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    if plaintext.len() % DES3_BLOCK != 0 {
        return Err(IkeError::Crypto("CBC plaintext not block-aligned"));
    }
    if key.len() != 24 {
        return Err(IkeError::Crypto("unsupported TripleDES-CBC key length (need 24 bytes)"));
    }
    let bad_key = || IkeError::Crypto("bad TripleDES-CBC key/iv");
    Ok(Des3CbcEnc::new_from_slices(key, iv).map_err(|_| bad_key())?.encrypt_padded_vec_mut::<NoPadding>(plaintext))
}

/// TripleDES-CBC decrypt (raw, no padding). See [`des3_cbc_encrypt`] for the
/// key-length requirement.
pub fn des3_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, IkeError> {
    if ciphertext.is_empty() || ciphertext.len() % DES3_BLOCK != 0 {
        return Err(IkeError::Crypto("CBC ciphertext not block-aligned"));
    }
    if key.len() != 24 {
        return Err(IkeError::Crypto("unsupported TripleDES-CBC key length (need 24 bytes)"));
    }
    let bad_key = || IkeError::Crypto("bad TripleDES-CBC key/iv");
    let bad_ct = || IkeError::Crypto("TripleDES-CBC decrypt failed");
    Des3CbcDec::new_from_slices(key, iv).map_err(|_| bad_key())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| bad_ct())
}

/// Dispatch to the AES-CBC or TripleDES-CBC primitive by block length -- the
/// two can't be told apart from the key alone (AES-192 and TripleDES-EDE3
/// both take a 24-byte key), so every caller past Phase 1 carries the
/// negotiated block length (see `Phase1State::enc_block`) alongside the key
/// rather than re-deriving the algorithm from it.
pub fn cbc_encrypt(block: usize, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    match block {
        AES_BLOCK => aes_cbc_encrypt(key, iv, plaintext),
        DES3_BLOCK => des3_cbc_encrypt(key, iv, plaintext),
        _ => Err(IkeError::Crypto("unsupported CBC block size")),
    }
}

/// See [`cbc_encrypt`].
pub fn cbc_decrypt(block: usize, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, IkeError> {
    match block {
        AES_BLOCK => aes_cbc_decrypt(key, iv, ciphertext),
        DES3_BLOCK => des3_cbc_decrypt(key, iv, ciphertext),
        _ => Err(IkeError::Crypto("unsupported CBC block size")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CKY_I: [u8; 8] = [0x11; 8];
    const CKY_R: [u8; 8] = [0x22; 8];

    #[test]
    fn skeyid_chain_is_deterministic_and_distinct() {
        for prf in [Prf::Sha1, Prf::Sha256] {
            let gxy = [0xAB; 128];
            let skeyid = skeyid_psk(prf, b"secret", &[1; 16], &[2; 16]);
            assert_eq!(skeyid.len(), prf.output_len());
            let d = skeyid_d(prf, &skeyid, &gxy, &CKY_I, &CKY_R);
            let a = skeyid_a(prf, &skeyid, &d, &gxy, &CKY_I, &CKY_R);
            let e = skeyid_e(prf, &skeyid, &a, &gxy, &CKY_I, &CKY_R);
            // Deterministic.
            assert_eq!(d, skeyid_d(prf, &skeyid, &gxy, &CKY_I, &CKY_R));
            // The three derived keys differ (the 0/1/2 counters).
            assert_ne!(d, a);
            assert_ne!(a, e);
            assert_ne!(d, e);
        }
    }

    #[test]
    fn skeyid_sig_matches_the_rfc_2409_formula_and_differs_from_skeyid_psk() {
        for prf in [Prf::Sha1, Prf::Sha256] {
            let (ni, nr, gxy) = (&[1u8; 16][..], &[2u8; 16][..], &[0xABu8; 128][..]);
            // §5.1: nonces are the PRF key, g^xy is the data -- the opposite
            // role assignment from §5.4's `skeyid_psk`.
            let got = skeyid_sig(prf, ni, nr, gxy);
            let expected = prf.mac(&cat(&[ni, nr]), gxy);
            assert_eq!(got, expected);
            assert_eq!(got.len(), prf.output_len());
            assert_ne!(got, skeyid_psk(prf, b"not actually used as a psk here", ni, nr));
        }
    }

    #[test]
    fn hash_i_and_hash_r_differ_by_argument_order() {
        let prf = Prf::Sha256;
        let skeyid = skeyid_psk(prf, b"psk", &[1; 16], &[2; 16]);
        let (gxi, gxr, sa, id) = ([0x01; 128], [0x02; 128], vec![0xAA; 16], vec![0xBB; 12]);
        let hi = hash_i(prf, &skeyid, &gxi, &gxr, &CKY_I, &CKY_R, &sa, &id);
        let hr = hash_r(prf, &skeyid, &gxr, &gxi, &CKY_R, &CKY_I, &sa, &id);
        assert_eq!(hi.len(), 32);
        assert_ne!(hi, hr, "HASH_I and HASH_R swap g^x and cookie order");
    }

    #[test]
    fn cipher_key_expansion_lengths() {
        // SHA-1 PRF (20 bytes) expanded to AES-256 (32 bytes) needs feedback.
        let e = vec![0x5A; 20];
        let k = derive_cipher_key(Prf::Sha1, &e, 32);
        assert_eq!(k.len(), 32);
        assert_eq!(derive_cipher_key(Prf::Sha1, &e, 32), k); // deterministic
        // SHA-256 SKEYID_e (32) already covers AES-256 → first 32 bytes.
        let e2 = vec![0x77; 32];
        assert_eq!(derive_cipher_key(Prf::Sha256, &e2, 32), e2);
    }

    #[test]
    fn aes_cbc_roundtrips_and_chains() {
        let key = [0x42; 32];
        let iv = phase1_iv(Prf::Sha256, &[0x01; 128], &[0x02; 128], AES_BLOCK);
        assert_eq!(iv.len(), AES_BLOCK);
        let plain = pad_to_block(b"an encrypted ISAKMP payload chain", AES_BLOCK);
        let ct = aes_cbc_encrypt(&key, &iv, &plain).unwrap();
        assert_eq!(ct.len(), plain.len());
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plain);
        // The next-message IV is the last ciphertext block.
        assert_eq!(next_iv(&ct, AES_BLOCK), ct[ct.len() - AES_BLOCK..]);
    }

    #[test]
    fn des3_cbc_matches_an_openssl_known_answer_and_dispatches_by_block() {
        // `printf 'The quick brown fox jump' | openssl enc -des-ede3-cbc -nopad
        //   -K 0123456789abcdef23456789abcdef01456789abcdef0123 -iv f69f2445df4f9b17`
        // -- an independent implementation, pinning the EDE3 key order and
        // the CBC chaining, not just an encrypt/decrypt roundtrip.
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
        ];
        let iv = [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17];
        let plain = b"The quick brown fox jump";
        let expected = [
            0x63, 0x69, 0x3c, 0x3d, 0x37, 0x8a, 0x86, 0x2f, 0x80, 0x51, 0xae, 0x7c, 0x29, 0x34, 0xa2, 0x96, 0xaa, 0x6c,
            0x31, 0x02, 0xb6, 0xe5, 0xb7, 0x9e,
        ];
        let ct = des3_cbc_encrypt(&key, &iv, plain).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(des3_cbc_decrypt(&key, &iv, &ct).unwrap(), plain);
        assert_eq!(next_iv(&ct, DES3_BLOCK), ct[ct.len() - DES3_BLOCK..]);

        // The dispatch selects TripleDES by block length -- a 24-byte key
        // alone would equally fit AES-192.
        assert_eq!(cbc_encrypt(DES3_BLOCK, &key, &iv, plain).unwrap(), expected);
        assert_eq!(cbc_decrypt(DES3_BLOCK, &key, &iv, &ct).unwrap(), plain);
        assert!(cbc_encrypt(12, &key, &iv, plain).is_err());

        // EDE3 only: no 16-byte two-key variant, no unaligned input.
        assert!(des3_cbc_encrypt(&key[..16], &iv, plain).is_err());
        assert!(des3_cbc_encrypt(&key, &iv, &plain[..20]).is_err());
        assert!(des3_cbc_decrypt(&key, &iv, &ct[..20]).is_err());
    }

    /// AES-128 and AES-192 must round-trip too (RFC 2409's `KEY_LENGTH`
    /// attribute selects the width -- a gateway policy pinned to AES-192
    /// (confirmed live against a real FortiGate) fails outright if this
    /// crate can only ever speak AES-256) and must not cross-decrypt with a
    /// different width, proving the dispatch in `aes_cbc_encrypt`/`_decrypt`
    /// actually picks a different cipher rather than silently truncating a
    /// 256-bit routine's key.
    #[test]
    fn aes_cbc_roundtrips_at_128_and_192_bits_and_widths_dont_cross_decrypt() {
        let iv = phase1_iv(Prf::Sha256, &[0x01; 128], &[0x02; 128], AES_BLOCK);
        let plain = pad_to_block(b"an encrypted ISAKMP payload chain", AES_BLOCK);
        for key_len in [16usize, 24] {
            let key = vec![0x42; key_len];
            let ct = aes_cbc_encrypt(&key, &iv, &plain).unwrap();
            assert_eq!(ct.len(), plain.len());
            let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
            assert_eq!(pt, plain);
        }
        let key128 = vec![0x42; 16];
        let key256 = vec![0x42; 32];
        let ct128 = aes_cbc_encrypt(&key128, &iv, &plain).unwrap();
        assert_ne!(ct128, aes_cbc_encrypt(&key256, &iv, &plain).unwrap());
        // Decrypting AES-128 ciphertext with an AES-256 key selects the
        // wrong cipher width (NoPadding never errors) -- must not silently
        // recover the right plaintext.
        assert_ne!(aes_cbc_decrypt(&key256, &iv, &ct128).unwrap(), plain);
    }

    #[test]
    fn phase2_iv_depends_on_message_id() {
        let p1 = phase1_iv(Prf::Sha256, &[0x01; 128], &[0x02; 128], AES_BLOCK);
        let a = phase2_iv(Prf::Sha256, &p1, 0x1234_5678, AES_BLOCK);
        let b = phase2_iv(Prf::Sha256, &p1, 0x1234_5679, AES_BLOCK);
        assert_eq!(a.len(), AES_BLOCK);
        assert_ne!(a, b);
    }

    #[test]
    fn keymat_fills_requested_length() {
        let km = keymat(Prf::Sha1, &[0x33; 20], 3, &[0xDE, 0xAD, 0xBE, 0xEF], &[1; 16], &[2; 16], 52);
        assert_eq!(km.len(), 52); // e.g. AES-256 (32) + HMAC-SHA1 (20)
        assert_ne!(km[..20], km[20..40]); // feedback blocks differ
    }
}
