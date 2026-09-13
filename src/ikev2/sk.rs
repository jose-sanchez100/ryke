//! The Encrypted (`SK{}`) payload (RFC 7296 §3.14), algorithm-agile.
//!
//! From `IKE_AUTH` onward, every payload travels inside an SK payload —
//! encrypted and authenticated under the keys derived in `IKE_SA_INIT`. Two
//! framings exist, chosen by [`SkCipher`] (which mirrors the ENCR/INTEG the
//! negotiated [`crate::ikev2::negotiate::ChosenSuite`] carries):
//!
//! - **AEAD** (AES-GCM-16 128/192/256, ChaCha20-Poly1305, RFC 5282/RFC 7634):
//!   `SK_e{i,r}` is the raw key ‖ a 4-byte salt. The nonce (12 bytes) is
//!   salt(4) ‖ explicit IV(8, sent in the payload). Associated Data = the IKE
//!   header ‖ the SK generic payload header. SK body on the wire = IV(8) ‖
//!   ciphertext ‖ ICV/tag(16).
//! - **Classic** (AES-CBC 128/192/256, 3DES-CBC, paired with a separate
//!   [`crate::crypto::IntegAlgorithm`]): `SK_e{i,r}` is the raw encryption key
//!   only (no salt); `SK_a{i,r}` is the separate integrity key. SK body on the
//!   wire = IV(block size) ‖ CBC-ciphertext(padded to a block multiple) ‖
//!   ICV, where the ICV is `IntegAlgorithm::compute` over the IKE header ‖ SK
//!   generic header ‖ IV ‖ ciphertext (RFC 7296 §3.14: everything from the
//!   fixed header through the end of the ciphertext, which for a non-AEAD
//!   scheme has no separate "additional data" concept — the MAC simply covers
//!   the whole message up to itself).
//!
//! [`build_encrypted_gcm`]/[`open_encrypted_gcm`] remain as thin AES-256-GCM-
//! only wrappers over the cipher-agile [`build_encrypted`]/[`open_encrypted`]
//! — kept for API stability (every existing test/caller of the GCM-only pair
//! still gets byte-identical behavior).

use aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::AesGcm;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::ChaCha20Poly1305;

use crate::crypto::IntegAlgorithm;
use crate::error::IkeError;
use crate::ikev2::message::{IkeHeader, PayloadType};
use crate::ikev2::negotiate::ChosenSuite;
use crate::ikev2::payload::transform_id;

const IV_LEN: usize = 8; // AEAD explicit IV
const AEAD_TAG_LEN: usize = 16;
const SALT_LEN: usize = 4;

type Aes128GcmC = aes_gcm::Aes128Gcm;
type Aes192GcmC = AesGcm<aes::Aes192, aead::consts::U12>;
type Aes256GcmC = aes_gcm::Aes256Gcm;
type ChaChaC = ChaCha20Poly1305;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type TdesCbcEnc = cbc::Encryptor<des::TdesEde3>;
type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

/// The negotiated SK{} cipher — the ENCR transform, plus (for a non-AEAD
/// ENCR) the INTEG transform it's paired with. Derived from a
/// [`ChosenSuite`] via [`SkCipher::from_chosen_suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkCipher {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Cbc(IntegAlgorithm),
    Aes192Cbc(IntegAlgorithm),
    Aes256Cbc(IntegAlgorithm),
    TripleDesCbc(IntegAlgorithm),
}

impl SkCipher {
    /// Map a negotiated suite to the cipher it implies, or `None` if the
    /// suite names an ENCR/INTEG combination this module doesn't implement.
    pub fn from_chosen_suite(suite: &ChosenSuite) -> Option<SkCipher> {
        Self::from_encr_integ(suite.encr_id, suite.encr_key_bits, suite.integ_id)
    }

    /// The primitive `(ENCR transform, key bits, optional INTEG transform)`
    /// → cipher mapping — shared by [`Self::from_chosen_suite`] (the IKE SA)
    /// and [`crate::ikev2::negotiate::ChosenEspSuite::sk_cipher`] (a CHILD
    /// SA's ESP/AH proposal, which carries the same ENCR/INTEG catalog but
    /// no PRF/DH of its own).
    pub fn from_encr_integ(encr_id: u16, encr_key_bits: u16, integ_id: Option<u16>) -> Option<SkCipher> {
        match encr_id {
            transform_id::AES_GCM_16 => match encr_key_bits {
                128 => Some(SkCipher::Aes128Gcm),
                192 => Some(SkCipher::Aes192Gcm),
                256 => Some(SkCipher::Aes256Gcm),
                _ => None,
            },
            transform_id::CHACHA20_POLY1305 => Some(SkCipher::ChaCha20Poly1305),
            transform_id::AES_CBC => {
                let integ = IntegAlgorithm::from_transform_id(integ_id?)?;
                match encr_key_bits {
                    128 => Some(SkCipher::Aes128Cbc(integ)),
                    192 => Some(SkCipher::Aes192Cbc(integ)),
                    256 => Some(SkCipher::Aes256Cbc(integ)),
                    _ => None,
                }
            }
            transform_id::TRIPLE_DES => IntegAlgorithm::from_transform_id(integ_id?).map(SkCipher::TripleDesCbc),
            _ => None,
        }
    }

    pub fn is_aead(self) -> bool {
        matches!(self, SkCipher::Aes128Gcm | SkCipher::Aes192Gcm | SkCipher::Aes256Gcm | SkCipher::ChaCha20Poly1305)
    }

    /// The raw encryption-key length (excludes the AEAD salt).
    pub fn key_len(self) -> usize {
        match self {
            SkCipher::Aes128Gcm | SkCipher::Aes128Cbc(_) => 16,
            SkCipher::Aes192Gcm | SkCipher::Aes192Cbc(_) => 24,
            SkCipher::Aes256Gcm | SkCipher::Aes256Cbc(_) | SkCipher::ChaCha20Poly1305 => 32,
            SkCipher::TripleDesCbc(_) => 24,
        }
    }

    /// AEAD salt length folded into `SK_e` (0 for a classic cipher, which
    /// instead has a separate `SK_a` integrity key).
    pub fn salt_len(self) -> usize {
        if self.is_aead() {
            SALT_LEN
        } else {
            0
        }
    }

    /// The block size (CBC IV length) for a classic cipher; meaningless for AEAD.
    pub(crate) fn block_len(self) -> usize {
        match self {
            SkCipher::TripleDesCbc(_) => 8,
            _ => 16,
        }
    }

    /// ICV/tag length appended to the wire.
    pub fn icv_len(self) -> usize {
        match self {
            SkCipher::Aes128Cbc(i) | SkCipher::Aes192Cbc(i) | SkCipher::Aes256Cbc(i) | SkCipher::TripleDesCbc(i) => {
                i.icv_len()
            }
            _ => AEAD_TAG_LEN,
        }
    }

    /// The paired integrity algorithm for a classic (non-AEAD) cipher;
    /// `None` for an AEAD cipher, which needs no separate integrity check.
    pub fn integ_algorithm(self) -> Option<IntegAlgorithm> {
        match self {
            SkCipher::Aes128Cbc(i) | SkCipher::Aes192Cbc(i) | SkCipher::Aes256Cbc(i) | SkCipher::TripleDesCbc(i) => Some(i),
            _ => None,
        }
    }
}

/// Split a 36-byte `SK_e` into (32-byte AES key, 4-byte salt) — the fixed
/// AES-256-GCM shape [`build_encrypted_gcm`]/[`open_encrypted_gcm`] use.
fn split_key(sk_e: &[u8]) -> Result<(&[u8], &[u8]), IkeError> {
    if sk_e.len() != 32 + SALT_LEN {
        return Err(IkeError::Crypto(
            "SK_e must be 36 bytes (32-byte AES-256 key + 4-byte GCM salt)",
        ));
    }
    Ok((&sk_e[..32], &sk_e[32..]))
}

pub(crate) fn aead_nonce(salt: &[u8], iv: &[u8; IV_LEN]) -> [u8; SALT_LEN + IV_LEN] {
    let mut nonce = [0u8; SALT_LEN + IV_LEN];
    nonce[..SALT_LEN].copy_from_slice(salt);
    nonce[SALT_LEN..].copy_from_slice(iv);
    nonce
}

fn aead_seal<C: Aead + AeadKeyInit>(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    let cipher = C::new_from_slice(key).map_err(|_| IkeError::Crypto("bad AEAD key length"))?;
    cipher
        .encrypt(aead::Nonce::<C>::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| IkeError::Crypto("AEAD encryption failed"))
}

fn aead_open<C: Aead + AeadKeyInit>(key: &[u8], nonce: &[u8], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>, IkeError> {
    let cipher = C::new_from_slice(key).map_err(|_| IkeError::Crypto("bad AEAD key length"))?;
    cipher
        .decrypt(aead::Nonce::<C>::from_slice(nonce), Payload { msg: ct_and_tag, aad })
        .map_err(|_| IkeError::BadIntegrity)
}

/// Low-level AES-256-GCM seal → ciphertext‖tag. Shared by the SK payload and by
/// SKF fragments ([`crate::ikev2::fragment`], which is AES-256-GCM-only today).
pub(crate) fn gcm_seal(sk_e: &[u8], iv: &[u8; IV_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    let (key, salt) = split_key(sk_e)?;
    aead_seal::<Aes256GcmC>(key, &aead_nonce(salt, iv), aad, plaintext)
}

/// Low-level AES-256-GCM open (verifies the tag) → plaintext.
pub(crate) fn gcm_open(sk_e: &[u8], iv: &[u8; IV_LEN], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>, IkeError> {
    let (key, salt) = split_key(sk_e)?;
    aead_open::<Aes256GcmC>(key, &aead_nonce(salt, iv), aad, ct_and_tag)
}

/// Expand an 8-byte caller-supplied fresh IV seed into a classic cipher's
/// actual wire IV length (16 bytes for AES-CBC, 8 for 3DES-CBC) via SHA-256
/// counter mode. AEAD ciphers use the 8 bytes directly as their explicit IV,
/// as `ryke` always has; a CBC IV must be exactly the block size and unique +
/// unpredictable per key, which expanding a fresh 8-byte value this way
/// satisfies — without widening the `iv: &[u8; 8]` shape every `IKE_AUTH`/
/// rekey call site across two repos already commits to.
fn expand_iv(seed: &[u8; 8], len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u8 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"ryke-ikev2-sk-cbc-iv");
        h.update(seed);
        h.update([counter]);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Constant-time byte-slice equality — avoids a timing side channel verifying
/// a classic cipher's HMAC ICV.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn sk_gen_header(first_inner: PayloadType, sk_payload_len: usize) -> [u8; 4] {
    let mut sk_gen = [0u8; 4];
    sk_gen[0] = first_inner.to_u8();
    sk_gen[2..4].copy_from_slice(&(sk_payload_len as u16).to_be_bytes());
    sk_gen
}

fn build_encrypted_aead(
    cipher: SkCipher,
    mut header: IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    sk_e: &[u8],
    iv: &[u8; IV_LEN],
) -> Result<Vec<u8>, IkeError> {
    let key_len = cipher.key_len();
    if sk_e.len() != key_len + SALT_LEN {
        return Err(IkeError::Crypto("SK_e has the wrong length for the negotiated AEAD cipher"));
    }
    let (key, salt) = sk_e.split_at(key_len);

    // Plaintext = inner ‖ pad_length(0). (AEAD needs no block padding; the
    // one-byte Pad Length field of RFC 7296 §3.14 is still required.)
    let mut plaintext = Vec::with_capacity(inner.len() + 1);
    plaintext.extend_from_slice(inner);
    plaintext.push(0);

    let sk_body_len = IV_LEN + plaintext.len() + cipher.icv_len();
    let sk_payload_len = 4 + sk_body_len;
    let total_len = IkeHeader::LEN + sk_payload_len;

    header.next_payload = PayloadType::Encrypted;
    header.length = total_len as u32;
    let header_bytes = header.to_bytes();
    let sk_gen = sk_gen_header(first_inner, sk_payload_len);

    // AAD = IKE header ‖ SK generic header (everything before the IV).
    let mut aad = Vec::with_capacity(header_bytes.len() + 4);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(&sk_gen);

    let nonce = aead_nonce(salt, iv);
    let ct_and_tag = match cipher {
        SkCipher::Aes128Gcm => aead_seal::<Aes128GcmC>(key, &nonce, &aad, &plaintext)?,
        SkCipher::Aes192Gcm => aead_seal::<Aes192GcmC>(key, &nonce, &aad, &plaintext)?,
        SkCipher::Aes256Gcm => aead_seal::<Aes256GcmC>(key, &nonce, &aad, &plaintext)?,
        SkCipher::ChaCha20Poly1305 => aead_seal::<ChaChaC>(key, &nonce, &aad, &plaintext)?,
        _ => unreachable!("build_encrypted_aead called with a non-AEAD cipher"),
    };

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&sk_gen);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct_and_tag);
    Ok(out)
}

fn open_encrypted_aead(cipher: SkCipher, message: &[u8], sk_e: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    let key_len = cipher.key_len();
    if sk_e.len() != key_len + SALT_LEN {
        return Err(IkeError::Crypto("SK_e has the wrong length for the negotiated AEAD cipher"));
    }
    let (key, salt) = sk_e.split_at(key_len);

    let header = IkeHeader::parse(message)?;
    if header.next_payload != PayloadType::Encrypted {
        return Err(IkeError::MissingPayload("SK"));
    }

    let body = &message[IkeHeader::LEN..];
    if body.len() < 4 {
        return Err(IkeError::Truncated { need: 4, have: body.len() });
    }
    let first_inner = PayloadType::from_u8(body[0]);
    let sk_payload_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if sk_payload_len < 4 + IV_LEN + cipher.icv_len() || sk_payload_len > body.len() {
        return Err(IkeError::BadLength { declared: sk_payload_len, available: body.len() });
    }

    let sk_body = &body[4..sk_payload_len];
    let iv: [u8; IV_LEN] = sk_body[..IV_LEN].try_into().unwrap();
    let ct_and_tag = &sk_body[IV_LEN..];

    let aad = &message[..IkeHeader::LEN + 4];
    let nonce = aead_nonce(salt, &iv);
    let plaintext = match cipher {
        SkCipher::Aes128Gcm => aead_open::<Aes128GcmC>(key, &nonce, aad, ct_and_tag)?,
        SkCipher::Aes192Gcm => aead_open::<Aes192GcmC>(key, &nonce, aad, ct_and_tag)?,
        SkCipher::Aes256Gcm => aead_open::<Aes256GcmC>(key, &nonce, aad, ct_and_tag)?,
        SkCipher::ChaCha20Poly1305 => aead_open::<ChaChaC>(key, &nonce, aad, ct_and_tag)?,
        _ => unreachable!("open_encrypted_aead called with a non-AEAD cipher"),
    };

    let pad_len = *plaintext.last().ok_or(IkeError::Crypto("empty plaintext"))? as usize;
    if pad_len + 1 > plaintext.len() {
        return Err(IkeError::Crypto("pad length exceeds plaintext"));
    }
    Ok((first_inner, plaintext[..plaintext.len() - 1 - pad_len].to_vec()))
}

/// AEAD seal, dispatching on `cipher` — shared by the SK{} payload
/// ([`build_encrypted`]) and the ESP CHILD SA data plane ([`crate::esp`]).
pub(crate) fn aead_seal_dispatch(cipher: SkCipher, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    match cipher {
        SkCipher::Aes128Gcm => aead_seal::<Aes128GcmC>(key, nonce, aad, plaintext),
        SkCipher::Aes192Gcm => aead_seal::<Aes192GcmC>(key, nonce, aad, plaintext),
        SkCipher::Aes256Gcm => aead_seal::<Aes256GcmC>(key, nonce, aad, plaintext),
        SkCipher::ChaCha20Poly1305 => aead_seal::<ChaChaC>(key, nonce, aad, plaintext),
        _ => unreachable!("aead_seal_dispatch called with a non-AEAD cipher"),
    }
}

/// AEAD open, dispatching on `cipher` — see [`aead_seal_dispatch`].
pub(crate) fn aead_open_dispatch(cipher: SkCipher, key: &[u8], nonce: &[u8], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>, IkeError> {
    match cipher {
        SkCipher::Aes128Gcm => aead_open::<Aes128GcmC>(key, nonce, aad, ct_and_tag),
        SkCipher::Aes192Gcm => aead_open::<Aes192GcmC>(key, nonce, aad, ct_and_tag),
        SkCipher::Aes256Gcm => aead_open::<Aes256GcmC>(key, nonce, aad, ct_and_tag),
        SkCipher::ChaCha20Poly1305 => aead_open::<ChaChaC>(key, nonce, aad, ct_and_tag),
        _ => unreachable!("aead_open_dispatch called with a non-AEAD cipher"),
    }
}

pub(crate) fn cbc_encrypt(cipher: SkCipher, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    let bad = || IkeError::Crypto("bad CBC key/iv length");
    Ok(match cipher {
        SkCipher::Aes128Cbc(_) => Aes128CbcEnc::new_from_slices(key, iv).map_err(|_| bad())?.encrypt_padded_vec_mut::<NoPadding>(plaintext),
        SkCipher::Aes192Cbc(_) => Aes192CbcEnc::new_from_slices(key, iv).map_err(|_| bad())?.encrypt_padded_vec_mut::<NoPadding>(plaintext),
        SkCipher::Aes256Cbc(_) => Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| bad())?.encrypt_padded_vec_mut::<NoPadding>(plaintext),
        SkCipher::TripleDesCbc(_) => TdesCbcEnc::new_from_slices(key, iv).map_err(|_| bad())?.encrypt_padded_vec_mut::<NoPadding>(plaintext),
        _ => unreachable!("cbc_encrypt called with a non-CBC cipher"),
    })
}

pub(crate) fn cbc_decrypt(cipher: SkCipher, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, IkeError> {
    let bad = || IkeError::Crypto("bad CBC key/iv length");
    let fail = || IkeError::Crypto("CBC decrypt failed");
    match cipher {
        SkCipher::Aes128Cbc(_) => Aes128CbcDec::new_from_slices(key, iv).map_err(|_| bad())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| fail()),
        SkCipher::Aes192Cbc(_) => Aes192CbcDec::new_from_slices(key, iv).map_err(|_| bad())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| fail()),
        SkCipher::Aes256Cbc(_) => Aes256CbcDec::new_from_slices(key, iv).map_err(|_| bad())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| fail()),
        SkCipher::TripleDesCbc(_) => TdesCbcDec::new_from_slices(key, iv).map_err(|_| bad())?.decrypt_padded_vec_mut::<NoPadding>(ciphertext).map_err(|_| fail()),
        _ => unreachable!("cbc_decrypt called with a non-CBC cipher"),
    }
}

fn cbc_integ(cipher: SkCipher) -> IntegAlgorithm {
    cipher.integ_algorithm().expect("cbc_integ called with a non-CBC cipher")
}

fn build_encrypted_cbc(
    cipher: SkCipher,
    mut header: IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    sk_e: &[u8],
    sk_a: &[u8],
    iv_seed: &[u8; IV_LEN],
) -> Result<Vec<u8>, IkeError> {
    let block = cipher.block_len();
    let icv_len = cipher.icv_len();
    let integ = cbc_integ(cipher);

    // Plaintext = inner ‖ padding ‖ pad_length byte, block-aligned. Pad bytes
    // are zero — RFC 7296 doesn't mandate specific pad byte values (unlike
    // ESP's 1,2,3,… convention), only that Pad Length be correct.
    let unpadded = inner.len() + 1;
    let pad = (block - (unpadded % block)) % block;
    let mut plaintext = Vec::with_capacity(inner.len() + pad + 1);
    plaintext.extend_from_slice(inner);
    plaintext.resize(plaintext.len() + pad, 0);
    plaintext.push(pad as u8);

    let iv = expand_iv(iv_seed, block);

    let sk_body_len = block + plaintext.len() + icv_len;
    let sk_payload_len = 4 + sk_body_len;
    let total_len = IkeHeader::LEN + sk_payload_len;

    header.next_payload = PayloadType::Encrypted;
    header.length = total_len as u32;
    let header_bytes = header.to_bytes();
    let sk_gen = sk_gen_header(first_inner, sk_payload_len);

    let ciphertext = cbc_encrypt(cipher, sk_e, &iv, &plaintext)?;

    // ICV = truncated HMAC over IKE header ‖ SK generic header ‖ IV ‖
    // ciphertext (RFC 7296 §3.14 — everything up to the ICV itself).
    let mut mac_input = Vec::with_capacity(header_bytes.len() + 4 + iv.len() + ciphertext.len());
    mac_input.extend_from_slice(&header_bytes);
    mac_input.extend_from_slice(&sk_gen);
    mac_input.extend_from_slice(&iv);
    mac_input.extend_from_slice(&ciphertext);
    let icv = integ.compute(sk_a, &mac_input);

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&sk_gen);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&icv);
    Ok(out)
}

fn open_encrypted_cbc(cipher: SkCipher, message: &[u8], sk_e: &[u8], sk_a: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    let block = cipher.block_len();
    let icv_len = cipher.icv_len();
    let integ = cbc_integ(cipher);

    let header = IkeHeader::parse(message)?;
    if header.next_payload != PayloadType::Encrypted {
        return Err(IkeError::MissingPayload("SK"));
    }
    let body = &message[IkeHeader::LEN..];
    if body.len() < 4 {
        return Err(IkeError::Truncated { need: 4, have: body.len() });
    }
    let first_inner = PayloadType::from_u8(body[0]);
    let sk_payload_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if sk_payload_len < 4 + block + icv_len || sk_payload_len > body.len() {
        return Err(IkeError::BadLength { declared: sk_payload_len, available: body.len() });
    }

    let sk_body = &body[4..sk_payload_len];
    let iv = &sk_body[..block];
    let ct = &sk_body[block..sk_body.len() - icv_len];
    let icv = &sk_body[sk_body.len() - icv_len..];
    if ct.is_empty() || ct.len() % block != 0 {
        return Err(IkeError::Crypto("CBC ciphertext not block-aligned"));
    }

    let mut mac_input = Vec::with_capacity(IkeHeader::LEN + 4 + iv.len() + ct.len());
    mac_input.extend_from_slice(&message[..IkeHeader::LEN + 4]);
    mac_input.extend_from_slice(iv);
    mac_input.extend_from_slice(ct);
    let expected_icv = integ.compute(sk_a, &mac_input);
    if !ct_eq(&expected_icv, icv) {
        return Err(IkeError::BadIntegrity);
    }

    let plaintext = cbc_decrypt(cipher, sk_e, iv, ct)?;
    let pad_len = *plaintext.last().ok_or(IkeError::Crypto("empty plaintext"))? as usize;
    if pad_len + 1 > plaintext.len() {
        return Err(IkeError::Crypto("pad length exceeds plaintext"));
    }
    Ok((first_inner, plaintext[..plaintext.len() - 1 - pad_len].to_vec()))
}

/// Build a complete encrypted IKEv2 message under the negotiated `cipher`:
/// IKE header + an SK payload wrapping `inner` (an already-serialized inner
/// payload chain). `first_inner` is the SK payload's Next Payload. `sk_e`
/// (and, for a classic cipher, `sk_a`) are the key material for our direction
/// — sized per `cipher.key_len()`(`+ salt_len()`) / the negotiated
/// [`IntegAlgorithm::key_len`]. `iv` must be a fresh, unique 8-byte value for
/// this key (see [`expand_iv`] for how a classic cipher gets its real IV from
/// this).
pub fn build_encrypted(
    cipher: SkCipher,
    header: IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    sk_e: &[u8],
    sk_a: &[u8],
    iv: &[u8; IV_LEN],
) -> Result<Vec<u8>, IkeError> {
    if cipher.is_aead() {
        build_encrypted_aead(cipher, header, first_inner, inner, sk_e, iv)
    } else {
        build_encrypted_cbc(cipher, header, first_inner, inner, sk_e, sk_a, iv)
    }
}

/// Decrypt the SK payload of a full message under the negotiated `cipher`,
/// returning the SK payload's Next Payload and the decrypted inner payload
/// chain (padding stripped). `sk_e`/`sk_a` are the key material for the
/// *sender's* direction.
pub fn open_encrypted(cipher: SkCipher, message: &[u8], sk_e: &[u8], sk_a: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    if cipher.is_aead() {
        open_encrypted_aead(cipher, message, sk_e)
    } else {
        open_encrypted_cbc(cipher, message, sk_e, sk_a)
    }
}

/// Build a complete encrypted IKEv2 message: IKE header + an SK payload wrapping
/// `inner` (an already-serialized inner payload chain). `first_inner` is the SK
/// payload's Next Payload (the type of the first inner payload). `sk_e` is the
/// 36-byte AES-GCM key material for our direction; `iv` must be a fresh, unique
/// 8-byte value for this key.
pub fn build_encrypted_gcm(
    header: IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    sk_e: &[u8],
    iv: &[u8; IV_LEN],
) -> Result<Vec<u8>, IkeError> {
    build_encrypted(SkCipher::Aes256Gcm, header, first_inner, inner, sk_e, &[], iv)
}

/// Decrypt the SK payload of a full message, returning the SK payload's Next
/// Payload (the first inner payload type) and the decrypted inner payload chain
/// (padding stripped). `sk_e` is the 36-byte AES-GCM key for the *sender's*
/// direction.
pub fn open_encrypted_gcm(message: &[u8], sk_e: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    open_encrypted(SkCipher::Aes256Gcm, message, sk_e, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::message::{ExchangeType, Flags};

    fn header() -> IkeHeader {
        IkeHeader {
            initiator_spi: 0x1111_2222_3333_4444,
            responder_spi: 0x5555_6666_7777_8888,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags { initiator: true, version: false, response: false },
            message_id: 1,
            length: 0,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let sk_e = [0x42u8; 36];
        let iv = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let inner = vec![0xABu8; 40];
        let msg = build_encrypted_gcm(header(), PayloadType::IdInitiator, &inner, &sk_e, &iv).unwrap();

        let h = IkeHeader::parse(&msg).unwrap();
        assert_eq!(h.next_payload, PayloadType::Encrypted);
        assert_eq!(h.length as usize, msg.len());

        let (first, out) = open_encrypted_gcm(&msg, &sk_e).unwrap();
        assert_eq!(first, PayloadType::IdInitiator);
        assert_eq!(out, inner);
    }

    #[test]
    fn empty_inner_roundtrips() {
        let sk_e = [5u8; 36];
        let msg = build_encrypted_gcm(header(), PayloadType::NoNext, &[], &sk_e, &[0u8; 8]).unwrap();
        let (first, out) = open_encrypted_gcm(&msg, &sk_e).unwrap();
        assert_eq!(first, PayloadType::NoNext);
        assert!(out.is_empty());
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let sk_e = [0x42u8; 36];
        let msg = build_encrypted_gcm(header(), PayloadType::Nonce, &[1, 2, 3, 4], &sk_e, &[9u8; 8]).unwrap();
        let mut bad = sk_e;
        bad[0] ^= 0xff;
        assert_eq!(open_encrypted_gcm(&msg, &bad).unwrap_err(), IkeError::BadIntegrity);
    }

    #[test]
    fn tampering_fails_authentication() {
        let sk_e = [7u8; 36];
        let mut msg = build_encrypted_gcm(header(), PayloadType::Nonce, &[9, 9, 9, 9], &sk_e, &[3u8; 8]).unwrap();
        let last = msg.len() - 1;
        msg[last] ^= 0x01; // flip a tag byte
        assert_eq!(open_encrypted_gcm(&msg, &sk_e).unwrap_err(), IkeError::BadIntegrity);
    }

    #[test]
    fn rejects_wrong_key_length() {
        let short = [0u8; 32]; // missing the 4-byte salt
        assert!(matches!(
            build_encrypted_gcm(header(), PayloadType::Nonce, &[], &short, &[0u8; 8]),
            Err(IkeError::Crypto(_))
        ));
    }

    fn aead_ciphers() -> Vec<SkCipher> {
        vec![SkCipher::Aes128Gcm, SkCipher::Aes192Gcm, SkCipher::Aes256Gcm, SkCipher::ChaCha20Poly1305]
    }

    fn cbc_ciphers() -> Vec<SkCipher> {
        use IntegAlgorithm::*;
        vec![
            SkCipher::Aes128Cbc(HmacSha2_256_128),
            SkCipher::Aes192Cbc(HmacSha1_96),
            SkCipher::Aes256Cbc(HmacSha2_512_256),
            SkCipher::TripleDesCbc(HmacMd5_96),
        ]
    }

    #[test]
    fn every_aead_cipher_roundtrips() {
        for cipher in aead_ciphers() {
            let sk_e = vec![0x24u8; cipher.key_len() + cipher.salt_len()];
            let inner = vec![0x77u8; 53];
            let msg = build_encrypted(cipher, header(), PayloadType::IdInitiator, &inner, &sk_e, &[], &[6u8; 8]).unwrap();
            let (first, out) = open_encrypted(cipher, &msg, &sk_e, &[]).unwrap();
            assert_eq!(first, PayloadType::IdInitiator, "{cipher:?}");
            assert_eq!(out, inner, "{cipher:?}");
        }
    }

    #[test]
    fn every_cbc_cipher_roundtrips_various_lengths() {
        for cipher in cbc_ciphers() {
            let (SkCipher::Aes128Cbc(integ) | SkCipher::Aes192Cbc(integ) | SkCipher::Aes256Cbc(integ) | SkCipher::TripleDesCbc(integ)) = cipher else {
                unreachable!()
            };
            let sk_e = vec![0x31u8; cipher.key_len()];
            let sk_a = vec![0x62u8; integ.key_len()];
            for len in [0usize, 1, 15, 16, 17, 40] {
                let inner = vec![0x99u8; len];
                let msg = build_encrypted(cipher, header(), PayloadType::Nonce, &inner, &sk_e, &sk_a, &[9u8; 8]).unwrap();
                let (first, out) = open_encrypted(cipher, &msg, &sk_e, &sk_a).unwrap();
                assert_eq!(first, PayloadType::Nonce, "{cipher:?} len={len}");
                assert_eq!(out, inner, "{cipher:?} len={len}");
            }
        }
    }

    #[test]
    fn cbc_wrong_integ_key_fails_authentication() {
        for cipher in cbc_ciphers() {
            let (SkCipher::Aes128Cbc(integ) | SkCipher::Aes192Cbc(integ) | SkCipher::Aes256Cbc(integ) | SkCipher::TripleDesCbc(integ)) = cipher else {
                unreachable!()
            };
            let sk_e = vec![0x11u8; cipher.key_len()];
            let sk_a = vec![0x22u8; integ.key_len()];
            let msg = build_encrypted(cipher, header(), PayloadType::Nonce, &[1, 2, 3], &sk_e, &sk_a, &[1u8; 8]).unwrap();
            let mut bad_sk_a = sk_a.clone();
            bad_sk_a[0] ^= 0xff;
            assert_eq!(open_encrypted(cipher, &msg, &sk_e, &bad_sk_a).unwrap_err(), IkeError::BadIntegrity, "{cipher:?}");
        }
    }

    #[test]
    fn cbc_tampering_fails_authentication() {
        for cipher in cbc_ciphers() {
            let (SkCipher::Aes128Cbc(integ) | SkCipher::Aes192Cbc(integ) | SkCipher::Aes256Cbc(integ) | SkCipher::TripleDesCbc(integ)) = cipher else {
                unreachable!()
            };
            let sk_e = vec![0x44u8; cipher.key_len()];
            let sk_a = vec![0x55u8; integ.key_len()];
            let mut msg = build_encrypted(cipher, header(), PayloadType::Nonce, &[9, 9, 9, 9], &sk_e, &sk_a, &[3u8; 8]).unwrap();
            let last = msg.len() - 1;
            msg[last] ^= 0x01;
            assert_eq!(open_encrypted(cipher, &msg, &sk_e, &sk_a).unwrap_err(), IkeError::BadIntegrity, "{cipher:?}");
        }
    }

    #[test]
    fn from_chosen_suite_maps_the_full_matrix() {
        use crate::ikev2::negotiate::ChosenSuite;

        let suite = |encr_id, encr_key_bits, integ_id: Option<u16>| ChosenSuite {
            proposal_num: 1,
            encr_id,
            encr_key_bits,
            prf_id: transform_id::PRF_HMAC_SHA2_256,
            integ_id,
            dh_id: transform_id::X25519,
        };

        assert_eq!(
            SkCipher::from_chosen_suite(&suite(transform_id::AES_GCM_16, 256, None)),
            Some(SkCipher::Aes256Gcm)
        );
        assert_eq!(
            SkCipher::from_chosen_suite(&suite(transform_id::CHACHA20_POLY1305, 256, None)),
            Some(SkCipher::ChaCha20Poly1305)
        );
        assert_eq!(
            SkCipher::from_chosen_suite(&suite(transform_id::AES_CBC, 128, Some(transform_id::AUTH_HMAC_SHA2_256_128))),
            Some(SkCipher::Aes128Cbc(IntegAlgorithm::HmacSha2_256_128))
        );
        assert_eq!(
            SkCipher::from_chosen_suite(&suite(transform_id::TRIPLE_DES, 192, Some(transform_id::AUTH_HMAC_MD5_96))),
            Some(SkCipher::TripleDesCbc(IntegAlgorithm::HmacMd5_96))
        );
        // A classic ENCR with no INTEG is unrepresentable — negotiate.rs never
        // produces this, but from_chosen_suite must still refuse it.
        assert_eq!(SkCipher::from_chosen_suite(&suite(transform_id::AES_CBC, 256, None)), None);
    }
}
